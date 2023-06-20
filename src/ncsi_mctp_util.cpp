#include "ncsi_mctp_util.hpp"
#include "ncsi_instance_id.hpp"

#include <iomanip>
#include <fmt/format.h>
#include <linux/ncsi.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace ncsi_mctp
{
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

/** @brief EID to NCSI Instance ID map */
std::map<uint8_t, InstanceId> ids;

void printBuffer(bool verbose, bool isTx, const std::vector<uint8_t>& buffer)
{
    if (!buffer.empty() && verbose) {
        std::ostringstream tempStream;
        for (int byte : buffer) {
            tempStream << std::setfill('0') << std::setw(2) << std::hex << byte
                       << " ";
        }
        if (isTx) {
            std::cout << "ncsi-mctp Tx: "
                      << tempStream.str()
                      << "\n";
        }
        else {
            std::cout << "ncsi-mctp Rx: "
                      << tempStream.str()
                      << "\n";
        }
    }
}

uint8_t getInstanceId(uint8_t eid)
{
    if (ids.find(eid) == ids.end()) {
        InstanceId id;
        ids.emplace(eid, InstanceId());
    }

    uint8_t id{};
    try {
        id = ids[eid].next();
    }
    catch (const std::runtime_error& e) {
        throw TooManyResources();
    }

    return id;
}

void markFree(uint8_t eid, uint8_t instanceId)
{
    ids[eid].markFree(instanceId);
}

static auto& getBus()
{
    static auto bus = sdbusplus::bus::new_default();
    return bus;
}

GetSubTreeResponse getSubtree(const std::string& searchPath, int depth,
                              const std::vector<std::string>& ifaceList)
{
    auto& bus = getBus();
    auto method = bus.new_method_call(mapperService, mapperPath,
                                      mapperInterface, "GetSubTree");
    method.append(searchPath, depth, ifaceList);
    auto reply = bus.call(method);
    GetSubTreeResponse response;
    reply.read(response);
    return response;
}

std::tuple<int, int, std::vector<uint8_t>> getMctpSockInfo(uint8_t remoteEID)
{
    int type = 0;
    int protocol = 0;
    std::vector<uint8_t> address{};
    auto& bus = getBus();
    const auto mctpEndpointIntfName{"xyz.openbmc_project.MCTP.Endpoint"};
    const auto unixSocketIntfName{"xyz.openbmc_project.Common.UnixSocket"};

    try {
        const Interfaces ifaceList{"xyz.openbmc_project.MCTP.Endpoint"};
        auto getSubTreeResponse = getSubtree(
            "/xyz/openbmc_project/mctp", 0, ifaceList);
        for (const auto& [objPath, mapperServiceMap] : getSubTreeResponse) {
            for (const auto& [serviceName, interfaces] : mapperServiceMap) {
                ObjectValueTree objects{};

                auto method = bus.new_method_call(
                    serviceName.c_str(), "/xyz/openbmc_project/mctp",
                    "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
                auto reply = bus.call(method);
                reply.read(objects);
                for (const auto& [objectPath, interfaces] : objects) {
                    if (interfaces.contains(mctpEndpointIntfName)) {
                        const auto& mctpProperties =
                            interfaces.at(mctpEndpointIntfName);
                        auto eid = std::get<size_t>(mctpProperties.at("EID"));
                        if (remoteEID == eid) {
                            if (interfaces.contains(unixSocketIntfName)) {
                                const auto& properties =
                                    interfaces.at(unixSocketIntfName);
                                type = std::get<size_t>(properties.at("Type"));
                                protocol =
                                    std::get<size_t>(properties.at("Protocol"));
                                address = std::get<std::vector<uint8_t>>(
                                    properties.at("Address"));
                                if (address.empty() || !type) {
                                    address.clear();
                                    return {0, 0, address};
                                } else {
                                    return {type, protocol, address};
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        address.clear();
        return {0, 0, address};
    }

    return {type, protocol, address};
}

ReturnInfo ncsiSendRecv(uint8_t eid,
                        std::vector<uint8_t>& requestMsg,
                        std::vector<uint8_t>& responseMsg,
                        bool verbose)
{
    std::string returnMsg;
    int rc = 0;

    /* Insert the NCSI message type and EID at the beginning of the msg */
    requestMsg.insert(requestMsg.begin(), MCTP_MSG_TYPE_NCSI);
    requestMsg.insert(requestMsg.begin(), eid);
    printBuffer(verbose, true, requestMsg);

    auto [type, protocol, sockAddress] = getMctpSockInfo(eid);
    if (sockAddress.empty()) {
        returnMsg = "Failed to get mctp socket info";
        rc = eid;
        logger(verbose, returnMsg, rc);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL, returnMsg, rc);
    }

    int sockFd = socket(AF_UNIX, type, protocol);
    struct timeval timeout;
	timeout.tv_sec = MCTP_CTRL_TXRX_TIMEOUT_5SECS;
	timeout.tv_usec = MCTP_CTRL_TXRX_TIMEOUT_MICRO_SECS;
    if (-1 == sockFd) {
        returnMsg = "Failed to create the socket";
        rc = -errno;
        logger(verbose, returnMsg, rc);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL, returnMsg, rc);
    }
    logger(verbose, "Success in creating the socket", sockFd);

    /* Register socket operations timeouts */
	if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
		sizeof(timeout)) < 0) {
        returnMsg = "Failed to register socket operations timeouts";
        rc = -errno;
        logger(verbose, returnMsg, rc);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL, returnMsg, rc);
	}
    logger(verbose, "Success in setting timeout for the socket", sockFd);

    CustomFD socketFd(sockFd);
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, sockAddress.data(), sockAddress.size());
    rc = connect(sockFd, reinterpret_cast<struct sockaddr*>(&addr),
                sockAddress.size() + sizeof(addr.sun_family));
    if (-1 == rc) {
        returnMsg = "Failed to connect to the socket";
        rc = -errno;
        logger(verbose, returnMsg, rc);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL, returnMsg, rc);
    }
    logger(verbose, "Success in connecting to socket", rc);

    auto ncsiType = MCTP_MSG_TYPE_NCSI;
    rc = write(sockFd, &ncsiType, sizeof(ncsiType));
    if (-1 == rc) {
        returnMsg = "Failed to send message type as ncsi to mctp demux daemon";
        rc = -errno;
        logger(verbose, returnMsg, rc);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_SEND_FAIL, returnMsg, rc);
    }
    logger(
        verbose,
        "Success in sending message type as ncsi to mctp demux daemon",
        rc);

    uint8_t* responseMessage = nullptr;
    size_t responseMessageSize{};
    ncsi_requester_rc_t ret;
    ret = ncsi_send_recv(eid, sockFd, requestMsg.data() + 2,
                    requestMsg.size() - 2, &responseMessage,
                    &responseMessageSize);
    responseMsg.resize(responseMessageSize);
    memcpy(responseMsg.data(), responseMessage, responseMsg.size());
    free(responseMessage);
    printBuffer(verbose, false, responseMsg);
    if (ret < 0) {
        returnMsg = "Failed to send and receive ncsi messages";
        rc = -errno;
        logger(verbose, returnMsg, ret);
        return std::make_tuple(NCSI_LOG_ERR, ret, returnMsg, rc);
    }
    logger(verbose, "Success in sending and receiving ncsi message", ret);

    return std::make_tuple(NCSI_LOG_INFO, NCSI_REQUESTER_SUCCESS, returnMsg, 0);
}

ReturnInfo applyCmd(int eid, const Command& cmd, int package = DEFAULT_VALUE,
             int channel = DEFAULT_VALUE, bool verbose = false)
{
    ReturnInfo ncsiInfo{};
    std::string returnMsg;
    int requestLen = 0;
    uint8_t instanceId = 0;
    uint32_t checksumVal = 0;
    uint32_t *pchecksum = nullptr;

    if (cmd.ncsi_cmd == DEFAULT_VALUE) {
        returnMsg = "Failed to set valid ncsi command";
        logger(verbose, returnMsg, cmd.ncsi_cmd);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL, returnMsg, cmd.ncsi_cmd);
    }

    instanceId = getInstanceId(eid);
    requestLen = sizeof(ncsi_pkt_hdr) + cmd.payload.size() + NCSI_CHECKSUM_LEN;
    std::vector<uint8_t> requestMsg(requestLen);
    ncsi_pkt_hdr* hdr = (ncsi_pkt_hdr*)requestMsg.data();
    std::copy(cmd.payload.begin(), cmd.payload.end(),
              requestMsg.begin() + sizeof(ncsi_pkt_hdr));
    hdr->MCID     = 0x0;
    hdr->revision = NCSI_PKT_REVISION;
    hdr->reserved = 0x0;
    hdr->id       = instanceId;
    hdr->type     = cmd.ncsi_cmd;
    hdr->length   = htons(cmd.payload.size());
    if (channel != DEFAULT_VALUE) {
        hdr->channel = NCSI_TO_CHANNEL(package, channel);
    }
	checksumVal = ncsi_calculate_checksum((unsigned char *)hdr,
					                       sizeof(*hdr) + cmd.payload.size());
    pchecksum = (uint32_t *)((uint8_t *)hdr + sizeof(struct ncsi_pkt_hdr) +
		        NLMSG_ALIGN(cmd.payload.size()));
    *pchecksum = htonl(checksumVal);

    std::vector<uint8_t> responseMsg;
    ncsiInfo = ncsiSendRecv(eid, requestMsg, responseMsg, verbose);

    markFree(eid, instanceId);
    return ncsiInfo;
}

int sendCommand(int eid, int package, int channel, int cmd,
                   std::span<const unsigned char> payload, bool verbose)
{
    ReturnInfo ncsiInfo{};

    if (verbose) {
        std::ios_base::fmtflags f( std::cout.flags() );
        std::cout << "Send NCSI Command, EID : " << std::hex << eid
                << ", PACKAGE : " << std::hex << package
                << ", CHANNEL : " << std::hex << channel
                << ", COMMAND : " << std::hex << cmd << std::endl;
        std::cout.flags( f );
        if (!payload.empty()) {
            std::cout << "PAYLOAD :";
            for (auto& i : payload) {
                std::cout << " " << std::hex << std::setfill('0') << std::setw(2)
                        << (int)i;
            }
            std::cout.flags( f );
            std::cout << std::endl;
        }
    }

    ncsiInfo = applyCmd(eid,
                    Command(NcsiMctpCommands::NCSI_CMD_SEND_RAW_CMD, cmd, payload),
                    package, channel, verbose);
    return std::get<1>(ncsiInfo);
}

} // namespace ncsi_mctp
} // namespace network
} // namespace phosphor
