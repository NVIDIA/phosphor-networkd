#ifndef NCSI_MCTP_H
#define NCSI_MCTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <libmctp-externals.h>

constexpr uint8_t MCTP_MSG_TYPE_NCSI = 2;
constexpr uint8_t MCTP_MSG_TAG_REQ = LIBMCTP_TAG_OWNER_MASK | MCTP_TAG_NCSI;
constexpr uint8_t MCTP_MSG_TAG_RSP = MCTP_TAG_NCSI;

typedef uint8_t mctp_eid_t;

typedef enum ncsi_requester_error_codes {
	NCSI_REQUESTER_SUCCESS = 0,
	NCSI_REQUESTER_OPEN_FAIL = -1,
	NCSI_REQUESTER_NOT_NCSI_MSG = -2,
	NCSI_REQUESTER_RESP_MSG_ERROR = -3,
	NCSI_REQUESTER_RECV_TIMEOUT = -4,
	NCSI_REQUESTER_RESP_MSG_TOO_SMALL = -5,
	NCSI_REQUESTER_INSTANCE_ID_MISMATCH = -6,
	NCSI_REQUESTER_SEND_FAIL = -7,
	NCSI_REQUESTER_RECV_FAIL = -8,
	NCSI_REQUESTER_INVALID_RECV_LEN = -9,
} ncsi_requester_rc_t;

typedef enum ncsi_requester_log_level {
	NCSI_LOG_ERR = 0x01,
	NCSI_LOG_WARNING = 0x02,
	NCSI_LOG_NOTICE = 0x03,
	NCSI_LOG_INFO = 0x04,
	NCSI_LOG_DEBUG = 0x05
} ncsi_requester_log_level_t;

/* MCTP TX/RX retry threshold */
#define MCTP_CMD_THRESHOLD 6

/* MCTP default Tx/Rx timeouts */
#define MCTP_CTRL_TXRX_TIMEOUT_5SECS 5
#define MCTP_CTRL_TXRX_TIMEOUT_19SECS 19
#define MCTP_CTRL_TXRX_TIMEOUT_MICRO_SECS 0

/* NCSI checksum length */
#define NCSI_CHECKSUM_LEN	0x04

/* NCSI packet revision */
#define NCSI_PKT_REVISION	0x01

/* NCSI packet commands */
#define NCSI_PKT_CMD_CIS	0x00 /* Clear Initial State              */
#define NCSI_PKT_CMD_SP		0x01 /* Select Package                   */
#define NCSI_PKT_CMD_DP		0x02 /* Deselect Package                 */
#define NCSI_PKT_CMD_EC		0x03 /* Enable Channel                   */
#define NCSI_PKT_CMD_DC		0x04 /* Disable Channel                  */
#define NCSI_PKT_CMD_RC		0x05 /* Reset Channel                    */
#define NCSI_PKT_CMD_ECNT	0x06 /* Enable Channel Network Tx        */
#define NCSI_PKT_CMD_DCNT	0x07 /* Disable Channel Network Tx       */
#define NCSI_PKT_CMD_AE		0x08 /* AEN Enable                       */
#define NCSI_PKT_CMD_SL		0x09 /* Set Link                         */
#define NCSI_PKT_CMD_GLS	0x0a /* Get Link                         */
#define NCSI_PKT_CMD_SVF	0x0b /* Set VLAN Filter                  */
#define NCSI_PKT_CMD_EV		0x0c /* Enable VLAN                      */
#define NCSI_PKT_CMD_DV		0x0d /* Disable VLAN                     */
#define NCSI_PKT_CMD_SMA	0x0e /* Set MAC address                  */
#define NCSI_PKT_CMD_EBF	0x10 /* Enable Broadcast Filter          */
#define NCSI_PKT_CMD_DBF	0x11 /* Disable Broadcast Filter         */
#define NCSI_PKT_CMD_EGMF	0x12 /* Enable Global Multicast Filter   */
#define NCSI_PKT_CMD_DGMF	0x13 /* Disable Global Multicast Filter  */
#define NCSI_PKT_CMD_SNFC	0x14 /* Set NCSI Flow Control            */
#define NCSI_PKT_CMD_GVI	0x15 /* Get Version ID                   */
#define NCSI_PKT_CMD_GC		0x16 /* Get Capabilities                 */
#define NCSI_PKT_CMD_GP		0x17 /* Get Parameters                   */
#define NCSI_PKT_CMD_GCPS	0x18 /* Get Controller Packet Statistics */
#define NCSI_PKT_CMD_GNS	0x19 /* Get NCSI Statistics              */
#define NCSI_PKT_CMD_GNPTS	0x1a /* Get NCSI Pass-throu Statistics   */
#define NCSI_PKT_CMD_GPS	0x1b /* Get package status               */
#define NCSI_PKT_CMD_OEM	0x50 /* OEM                              */
#define NCSI_PKT_CMD_PLDM	0x51 /* PLDM request over NCSI over RBT  */
#define NCSI_PKT_CMD_GPUUID	0x52 /* Get package UUID                 */
#define NCSI_PKT_CMD_QPNPR	0x56 /* Query Pending NC PLDM request */
#define NCSI_PKT_CMD_SNPR	0x57 /* Send NC PLDM Reply  */

/* NCSI response code/reason */
#define NCSI_PKT_RSP_C_COMPLETED	0x0000 /* Command Completed        */
#define NCSI_PKT_RSP_C_FAILED		0x0001 /* Command Failed           */
#define NCSI_PKT_RSP_C_UNAVAILABLE	0x0002 /* Command Unavailable      */
#define NCSI_PKT_RSP_C_UNSUPPORTED	0x0003 /* Command Unsupported      */
#define NCSI_PKT_RSP_R_NO_ERROR		0x0000 /* No Error                 */
#define NCSI_PKT_RSP_R_INTERFACE	0x0001 /* Interface not ready      */
#define NCSI_PKT_RSP_R_PARAM		0x0002 /* Invalid Parameter        */
#define NCSI_PKT_RSP_R_CHANNEL		0x0003 /* Channel not Ready        */
#define NCSI_PKT_RSP_R_PACKAGE		0x0004 /* Package not Ready        */
#define NCSI_PKT_RSP_R_LENGTH		0x0005 /* Invalid payload length   */
#define NCSI_PKT_RSP_R_UNKNOWN		0x7fff /* Command type unsupported */

/* OEM Vendor Manufacture ID */
#define NCSI_OEM_MFR_MLX_ID             0x8119
#define NCSI_OEM_MFR_BCM_ID             0x113d
#define NCSI_OEM_MFR_INTEL_ID           0x157

/* NCSI packet header */
struct ncsi_pkt_hdr {
    uint8_t MCID;
    uint8_t revision;
    uint8_t reserved;
    uint8_t id;
    uint8_t type;
    uint8_t channel;
    uint16_t length;
    uint32_t rsvd[2];
} __attribute__((packed));

/* NCSI response packet header */
struct ncsi_rsp_pkt_hdr {
	struct ncsi_pkt_hdr common; /* Common NCSI packet header */
	uint16_t              code; /* Response code             */
	uint16_t            reason; /* Response reason           */
} __attribute__((packed));

/* Structure representing NCSI message */
struct ncsi_msg {
	struct ncsi_pkt_hdr hdr; //!< NCSI message header
	uint8_t payload[1]; //!< &payload[0] is the beginning of the payload
} __attribute__((packed));

/* OEM Response Packet as per NCSI Specification */
struct ncsi_rsp_oem_pkt {
	struct ncsi_rsp_pkt_hdr rsp;         /* Command header    */
	uint32_t                mfr_id;      /* Manufacture ID    */
	uint32_t                payload[1];      /* Payload data      */
}__attribute__((packed));

/**
 * @brief Send a NCSI request message. Wait for corresponding response message,
 *        which once received, is returned to the caller.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[in] ncsi_req_msg - caller owned pointer to NCSI request msg
 * @param[in] req_msg_len - size of NCSI request msg
 * @param[out] ncsi_resp_msg - *ncsi_resp_msg will point to NCSI response msg,
 *             this function allocates memory, caller to free(*ncsi_resp_msg) on
 *             success.
 * @param[out] resp_msg_len - caller owned pointer that will be made point to
 *             the size of the NCSI response msg.
 *
 * @return ncsi_requester_rc_t (errno may be set)
 */
ncsi_requester_rc_t ncsi_send_recv(mctp_eid_t eid, int mctp_fd,
				   const uint8_t *ncsi_req_msg,
				   size_t req_msg_len, uint8_t **ncsi_resp_msg,
				   size_t *resp_msg_len);

/**
 * @brief Send a NCSI request message, don't wait for response. Essentially an
 *        async API. A user of this would typically have added the MCTP fd to an
 *        event loop for polling. Once there's data available, the user would
 *        invoke ncsi_recv().
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[in] ncsi_req_msg - caller owned pointer to NCSI request msg
 * @param[in] req_msg_len - size of NCSI request msg
 *
 * @return ncsi_requester_rc_t (errno may be set)
 */
ncsi_requester_rc_t ncsi_send(mctp_eid_t eid, int mctp_fd,
			      const uint8_t *ncsi_req_msg, size_t req_msg_len);

/**
 * @brief Read MCTP socket. If there's data available, return success only if
 *        data is a NCSI response message that matches eid and instance_id.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[in] instance_id - NCSI instance id of previously sent NCSI request msg
 * @param[out] ncsi_resp_msg - *ncsi_resp_msg will point to NCSI response msg,
 *             this function allocates memory, caller to free(*ncsi_resp_msg) on
 *             success.
 * @param[out] resp_msg_len - caller owned pointer that will be made point to
 *             the size of the NCSI response msg.
 *
 * @return ncsi_requester_rc_t (errno may be set). failure is returned even
 *         when data was read, but didn't match eid or instance_id.
 */
ncsi_requester_rc_t ncsi_recv(mctp_eid_t eid, int mctp_fd, uint8_t instance_id,
			      uint8_t **ncsi_resp_msg, size_t *resp_msg_len);

/**
 * @brief Read MCTP socket. If there's data available, return success only if
 *        data is a NCSI response message.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[out] ncsi_resp_msg - *ncsi_resp_msg will point to NCSI response msg,
 *             this function allocates memory, caller to free(*ncsi_resp_msg) on
 *             success.
 * @param[out] resp_msg_len - caller owned pointer that will be made point to
 *             the size of the NCSI response msg.
 *
 * @return ncsi_requester_rc_t (errno may be set). failure is returned even
 *         when data was read, but wasn't a NCSI response message
 */
ncsi_requester_rc_t ncsi_recv_any(mctp_eid_t eid, int mctp_fd,
				  uint8_t **ncsi_resp_msg,
				  size_t *resp_msg_len);

/**
 * @brief Calculate NCSI checksum. Return the checksum value for the NCSI
 *        Control Packet.
 *
 * @param[in] data - caller owned pointer to NCSI message header.
 * @param[in] len - length of the NCSI packet.
 *
 * @return checksum for the NCSI request message.
 */
uint32_t ncsi_calculate_checksum(unsigned char *data, int len);

#ifdef __cplusplus
}
#endif

#endif /* NCSI_MCTP_H */
