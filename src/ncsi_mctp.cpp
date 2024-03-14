#include "ncsi_mctp.hpp"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/time.h>
#include <linux/ncsi.h>
#include <time.h>

#include <memory>
/**
 * @brief Read MCTP socket. If there's data available, return success only if
 *        data is a NCSI message.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[out] ncsi_resp_msg - *ncsi_resp_msg will point to NCSI msg,
 *             this function allocates memory, caller to free(*ncsi_resp_msg) on
 *             success.
 * @param[out] resp_msg_len - caller owned pointer that will be made point to
 *             the size of the NCSI msg.
 *
 * @return ncsi_requester_rc_t (errno may be set). failure is returned even
 *         when data was read, but wasn't a NCSI response message
 */
static ncsi_requester_rc_t mctp_recv(mctp_eid_t eid, int mctp_fd,
				     uint8_t **ncsi_resp_msg,
				     size_t *resp_msg_len)
{
	uint8_t msgTag = 0;
	ssize_t min_len = sizeof(msgTag) + sizeof(eid) + sizeof(MCTP_MSG_TYPE_NCSI) +
			  sizeof(struct ncsi_pkt_hdr);
	ssize_t length = recv(mctp_fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
	if (length <= 0) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
			return NCSI_REQUESTER_RECV_TIMEOUT;
		} else {
			return NCSI_REQUESTER_RECV_FAIL;
		}
	} else if (length < min_len) {
		/* read and discard */
		std::unique_ptr<uint8_t> buf = std::make_unique<uint8_t>(length);
		(void)recv(mctp_fd, buf.get(), length, 0);
		return NCSI_REQUESTER_RESP_MSG_TOO_SMALL;
	} else {
		struct iovec iov[2];
		size_t mctp_prefix_len =
		    sizeof(msgTag) + sizeof(eid) + sizeof(MCTP_MSG_TYPE_NCSI);
		std::unique_ptr<uint8_t> mctp_prefix = std::make_unique<uint8_t>(mctp_prefix_len);
		size_t ncsi_len = length - mctp_prefix_len;
		iov[0].iov_len = mctp_prefix_len;
		iov[0].iov_base = mctp_prefix.get();
		*ncsi_resp_msg = (uint8_t *)malloc(ncsi_len);
		iov[1].iov_len = ncsi_len;
		iov[1].iov_base = *ncsi_resp_msg;
		struct msghdr msg = {};
		msg.msg_iov = iov;
		msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
		ssize_t bytes = recvmsg(mctp_fd, &msg, 0);
		*resp_msg_len = ncsi_len;
		if (length != bytes) {
			return NCSI_REQUESTER_INVALID_RECV_LEN;
		}
		if ((mctp_prefix.get()[0] != MCTP_MSG_TAG_RSP) ||
		    (mctp_prefix.get()[1] != eid) ||
		    (mctp_prefix.get()[2] != MCTP_MSG_TYPE_NCSI)) {
			return NCSI_REQUESTER_NOT_NCSI_MSG;
		}
		return NCSI_REQUESTER_SUCCESS;
	}
}

ncsi_requester_rc_t ncsi_recv_any(mctp_eid_t eid, int mctp_fd,
				  uint8_t **ncsi_resp_msg, size_t *resp_msg_len)
{
	ncsi_requester_rc_t rc =
	    mctp_recv(eid, mctp_fd, ncsi_resp_msg, resp_msg_len);
	if (rc != NCSI_REQUESTER_SUCCESS) {
		return rc;
	}

	struct ncsi_rsp_pkt_hdr *hdr = (struct ncsi_rsp_pkt_hdr *)(*ncsi_resp_msg);
	if (hdr->code != NCSI_PKT_RSP_C_COMPLETED ||
	    hdr->reason != NCSI_PKT_RSP_R_NO_ERROR) {
		return NCSI_REQUESTER_RESP_MSG_ERROR;
	}

	uint32_t ncsi_rc = 0;
	if (*resp_msg_len < (sizeof(struct ncsi_pkt_hdr) + sizeof(ncsi_rc))) {
		return NCSI_REQUESTER_INVALID_RECV_LEN;
	}

	return NCSI_REQUESTER_SUCCESS;
}

ncsi_requester_rc_t ncsi_recv(mctp_eid_t eid, int mctp_fd, uint8_t instance_id,
			      uint8_t **ncsi_resp_msg, size_t *resp_msg_len)
{
	ncsi_requester_rc_t rc =
	    ncsi_recv_any(eid, mctp_fd, ncsi_resp_msg, resp_msg_len);
	if (rc != NCSI_REQUESTER_SUCCESS) {
		return rc;
	}

	struct ncsi_pkt_hdr *hdr = (struct ncsi_pkt_hdr *)(*ncsi_resp_msg);
	if (hdr->id != instance_id) {
		return NCSI_REQUESTER_INSTANCE_ID_MISMATCH;
	}

	return NCSI_REQUESTER_SUCCESS;
}

ncsi_requester_rc_t ncsi_send_recv(mctp_eid_t eid, int mctp_fd,
				   const uint8_t *ncsi_req_msg,
				   size_t req_msg_len, uint8_t **ncsi_resp_msg,
				   size_t *resp_msg_len)
{
	struct ncsi_pkt_hdr *hdr = (struct ncsi_pkt_hdr *)ncsi_req_msg;
	struct timespec now = {};
	struct timespec prev = {};
	int retry_count = 0;

	ncsi_requester_rc_t rc =
	    ncsi_send(eid, mctp_fd, ncsi_req_msg, req_msg_len);
	if (rc != NCSI_REQUESTER_SUCCESS) {
		return rc;
	}
	clock_gettime(CLOCK_MONOTONIC, &prev);

	while (1) {
		rc = ncsi_recv(eid, mctp_fd, hdr->id, ncsi_resp_msg,
			       resp_msg_len);
		/* If valid data received, break the loop and return the message */
		if (rc != NCSI_REQUESTER_RECV_TIMEOUT &&
			rc != NCSI_REQUESTER_RECV_FAIL &&
			rc != NCSI_REQUESTER_RESP_MSG_TOO_SMALL) {
			break;
		}
		clock_gettime(CLOCK_MONOTONIC , &now);
		if (((now.tv_sec - prev.tv_sec) > MCTP_CTRL_TXRX_TIMEOUT_19SECS) ||
		    (retry_count == MCTP_CMD_THRESHOLD)) {
			break;
		}
		/* Increment the retry count */
		retry_count++;
	}

	return rc;
}

ncsi_requester_rc_t ncsi_send(mctp_eid_t eid, int mctp_fd,
			      const uint8_t *ncsi_req_msg, size_t req_msg_len)
{
	uint8_t hdr[3] = {MCTP_MSG_TAG_REQ, eid, MCTP_MSG_TYPE_NCSI};

	struct iovec iov[2];
	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = (uint8_t *)ncsi_req_msg;
	iov[1].iov_len = req_msg_len;

	struct msghdr msg = {};
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

	ssize_t rc = sendmsg(mctp_fd, &msg, 0);
	if (rc == -1) {
		return NCSI_REQUESTER_SEND_FAIL;
	}

	return NCSI_REQUESTER_SUCCESS;
}

uint32_t ncsi_calculate_checksum(unsigned char *data, int len)
{
	uint32_t checksum = 0;
	int i;

	for (i = 0; i < len; i += 2)
		checksum += (((uint32_t)data[i] << 8) | data[i + 1]);

	checksum = (~checksum + 1);
	return checksum;
}
