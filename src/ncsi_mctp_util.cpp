#include "ncsi_mctp_util.hpp"

#include "ncsi_instance_id.hpp"

#include <arpa/inet.h>
#include <fmt/format.h>
#include <linux/ncsi.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <functional>
#include <unordered_map>

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
    if (!buffer.empty() && verbose)
    {
        std::ostringstream tempStream;
        for (int byte : buffer)
        {
            tempStream << std::setfill('0') << std::setw(2) << std::hex << byte
                       << " ";
        }
        if (isTx)
        {
            std::cout << "ncsi-mctp Tx: " << tempStream.str() << "\n";
        }
        else
        {
            std::cout << "ncsi-mctp Rx: " << tempStream.str() << "\n";
        }
    }
}

uint8_t getInstanceId(uint8_t eid)
{
    if (ids.find(eid) == ids.end())
    {
        ids.emplace(eid, InstanceId());
    }

    uint8_t id{};
    try
    {
        id = ids[eid].next();
    }
    catch (const std::runtime_error& e)
    {
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

    try
    {
        const Interfaces ifaceList{"xyz.openbmc_project.MCTP.Endpoint"};
        auto getSubTreeResponse = getSubtree("/xyz/openbmc_project/mctp", 0,
                                             std::move(ifaceList));
        for (const auto& [objPath, mapperServiceMap] : getSubTreeResponse)
        {
            for (const auto& [serviceName, interfaces] : mapperServiceMap)
            {
                ObjectValueTree objects{};

                auto method = bus.new_method_call(
                    serviceName.c_str(), "/xyz/openbmc_project/mctp",
                    "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
                auto reply = bus.call(method);
                reply.read(objects);
                for (const auto& [objectPath, interfaces] : objects)
                {
                    if (interfaces.contains(mctpEndpointIntfName))
                    {
                        const auto& mctpProperties =
                            interfaces.at(mctpEndpointIntfName);
                        auto eid = std::get<size_t>(mctpProperties.at("EID"));
                        if (remoteEID == eid)
                        {
                            if (interfaces.contains(unixSocketIntfName))
                            {
                                const auto& properties =
                                    interfaces.at(unixSocketIntfName);
                                type = std::get<size_t>(properties.at("Type"));
                                protocol =
                                    std::get<size_t>(properties.at("Protocol"));
                                address = std::get<std::vector<uint8_t>>(
                                    properties.at("Address"));
                                if (address.empty() || !type)
                                {
                                    address.clear();
                                    return {0, 0, address};
                                }
                                else
                                {
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

ReturnInfo ncsiSendRecv(uint8_t eid, std::vector<uint8_t>& requestMsg,
                        std::vector<uint8_t>& responseMsg, bool verbose)
{
    std::string returnMsg;
    int rc = 0;

    /* Insert the NCSI message type and EID at the beginning of the msg */
    requestMsg.insert(requestMsg.begin(), MCTP_MSG_TYPE_NCSI);
    requestMsg.insert(requestMsg.begin(), eid);
    printBuffer(verbose, true, requestMsg);

    auto [type, protocol, sockAddress] = getMctpSockInfo(eid);
    if (sockAddress.empty())
    {
        returnMsg = "Failed to get mctp socket info";
        rc = eid;
        logger(verbose, returnMsg, rc);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL,
                               returnMsg, rc);
    }

    int sockFd = socket(AF_UNIX, type, protocol);
    struct timeval timeout;
    timeout.tv_sec = MCTP_CTRL_TXRX_TIMEOUT_5SECS;
    timeout.tv_usec = MCTP_CTRL_TXRX_TIMEOUT_MICRO_SECS;
    if (-1 == sockFd)
    {
        returnMsg = "Failed to create the socket";
        rc = -errno;
        logger(verbose, returnMsg, rc);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL,
                               returnMsg, rc);
    }
    logger(verbose, "Success in creating the socket", sockFd);

    /* Register socket operations timeouts */
    if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout,
                   sizeof(timeout)) < 0)
    {
        returnMsg = "Failed to register socket operations timeouts";
        rc = -errno;
        logger(verbose, returnMsg, rc);
        close(sockFd);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL,
                               returnMsg, rc);
    }
    logger(verbose, "Success in setting timeout for the socket", sockFd);

    CustomFD socketFd(sockFd);
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, sockAddress.data(), sockAddress.size());
    rc = connect(socketFd(), reinterpret_cast<struct sockaddr*>(&addr),
                 sockAddress.size() + sizeof(addr.sun_family));
    if (-1 == rc)
    {
        returnMsg = "Failed to connect to the socket";
        rc = -errno;
        logger(verbose, returnMsg, rc);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL,
                               returnMsg, rc);
    }
    logger(verbose, "Success in connecting to socket", rc);

    auto ncsiType = MCTP_MSG_TYPE_NCSI;
    rc = write(socketFd(), &ncsiType, sizeof(ncsiType));
    if (-1 == rc)
    {
        returnMsg = "Failed to send message type as ncsi to mctp demux daemon";
        rc = -errno;
        logger(verbose, returnMsg, rc);
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_SEND_FAIL,
                               returnMsg, rc);
    }
    logger(verbose,
           "Success in sending message type as ncsi to mctp demux daemon", rc);

    uint8_t* responseMessage = nullptr;
    size_t responseMessageSize{};
    ncsi_requester_rc_t ret;
    ret = ncsi_send_recv(eid, sockFd, requestMsg.data() + 2,
                         requestMsg.size() - 2, &responseMessage,
                         &responseMessageSize);
    if (responseMessageSize > 0)
    {
        responseMsg.resize(responseMessageSize);
        memcpy(responseMsg.data(), responseMessage, responseMsg.size());
        printBuffer(verbose, false, responseMsg);
        free(responseMessage);
    }
    if (ret < 0)
    {
        returnMsg = "Failed to send and receive ncsi messages";
        rc = -errno;
        logger(verbose, returnMsg, ret);
        return std::make_tuple(NCSI_LOG_ERR, ret, returnMsg, rc);
    }
    logger(verbose, "Success in sending and receiving ncsi message", ret);

    return std::make_tuple(NCSI_LOG_INFO, NCSI_REQUESTER_SUCCESS, returnMsg, 0);
}

/** @brief Display in JSON format.
 *
 *  @param[in]  data - data to print in json
 *
 *  @return - None
 */
static inline void DisplayInJson(const ordered_json& data)
{
    std::cout << data.dump(4) << std::endl;
}

static const std::unordered_map<uint32_t, std::string> oemVendorManufactures = {
    {NCSI_OEM_MFR_MLX_ID, "MLX"},
    {NCSI_OEM_MFR_BCM_ID, "BCM"},
    {NCSI_OEM_MFR_INTEL_ID, "INTEL"}};

template <typename INT_TYPE>
static inline std::string to_hex_string(INT_TYPE val)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(sizeof(INT_TYPE) * 2)
       << val;
    return ss.str();
}

ordered_json parseOemResponseMsg(struct ncsi_rsp_pkt_hdr* responsePtr,
                                 size_t payloadLength)
{
    ordered_json data;
    ncsi_rsp_oem_pkt* oemResponsePtr =
        reinterpret_cast<struct ncsi_rsp_oem_pkt*>(responsePtr);
    payloadLength -= (sizeof(ncsi_rsp_pkt_hdr) - sizeof(ncsi_pkt_hdr));

    auto it = oemVendorManufactures.find(ntohl(oemResponsePtr->mfr_id));
    if (it != oemVendorManufactures.end())
    {
        data["Manufacture_ID"] = it->second;
    }
    else
    {
        data["Manufacture_ID"] =
            "Unknown Id(0x" +
            to_hex_string<uint32_t>(htonl(oemResponsePtr->mfr_id)) + ")";
    }

    payloadLength -= sizeof(oemResponsePtr->mfr_id);
    int len = payloadLength / sizeof(uint32_t);
    ordered_json oem_payload = nlohmann::json::array();

    for (int i = 0; i < len; ++i)
    {
        oem_payload.push_back(
            "0x" + to_hex_string<uint32_t>(oemResponsePtr->payload[i]));
    }
    data["OEM_Payload"] = oem_payload;

    return data;
}

static const std::unordered_map<
    uint8_t, std::function<ordered_json(struct ncsi_rsp_pkt_hdr*, size_t)>>
    handledResponseMsg = {{0xD0, parseOemResponseMsg}};

void parseResponseMsg(struct ncsi_rsp_pkt_hdr* responsePtr,
                      ReturnInfo& ncsiInfo, size_t payloadLength)
{
    ordered_json data;
    auto rc = std::get<1>(ncsiInfo);

    if (rc)
    {
        data["Error"]["Code"] = rc;
        data["Error"]["Message"] = std::get<2>(ncsiInfo);
        data["Error"]["Data"] = std::get<3>(ncsiInfo);
        // incase of error in response message print response message
        if (rc != NCSI_REQUESTER_RESP_MSG_ERROR)
        {
            DisplayInJson(data);
            return;
        }
    }

    data["Code"] = (int)ntohs(responsePtr->code);
    data["Reason"] = (int)ntohs(responsePtr->reason);
    auto it = handledResponseMsg.find(responsePtr->common.type);
    if (it != handledResponseMsg.end())
    {
        data.update(it->second(responsePtr, payloadLength));
    }

    DisplayInJson(data);
}

ReturnInfo applyCmd(int eid, const Command& cmd,
                    std::vector<uint8_t>& responseMsg,
                    int package = DEFAULT_VALUE, int channel = DEFAULT_VALUE,
                    bool verbose = false)
{
    ReturnInfo ncsiInfo{};
    std::string returnMsg;
    int requestLen = 0;
    uint8_t instanceId = 0;
    uint32_t checksumVal = 0;
    uint32_t* pchecksum = nullptr;

    try
    {
        if (cmd.ncsi_cmd == DEFAULT_VALUE)
        {
            returnMsg = "Failed to set valid ncsi command";
            logger(verbose, returnMsg, cmd.ncsi_cmd);
            return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_OPEN_FAIL,
                                   returnMsg, cmd.ncsi_cmd);
        }

        instanceId = getInstanceId(eid);
        requestLen = sizeof(ncsi_pkt_hdr) + cmd.payload.size() +
                     NCSI_CHECKSUM_LEN;
        std::vector<uint8_t> requestMsg(requestLen);
        ncsi_pkt_hdr* hdr = (ncsi_pkt_hdr*)requestMsg.data();
        std::copy(cmd.payload.begin(), cmd.payload.end(),
                  requestMsg.begin() + sizeof(ncsi_pkt_hdr));
        hdr->MCID = 0x0;
        hdr->revision = NCSI_PKT_REVISION;
        hdr->reserved = 0x0;
        hdr->id = instanceId;
        hdr->type = cmd.ncsi_cmd;
        hdr->length = htons(cmd.payload.size());
        if (channel != DEFAULT_VALUE)
        {
            hdr->channel = NCSI_TO_CHANNEL(package, channel);
        }
        checksumVal = ncsi_calculate_checksum(
            (unsigned char*)hdr, sizeof(*hdr) + cmd.payload.size());
        pchecksum = (uint32_t*)((uint8_t*)hdr + sizeof(struct ncsi_pkt_hdr) +
                                NLMSG_ALIGN(cmd.payload.size()));
        *pchecksum = htonl(checksumVal);

        ncsiInfo = ncsiSendRecv(eid, requestMsg, responseMsg, verbose);
        markFree(eid, instanceId);
    }
    catch (const std::exception& e)
    {
        std::string returnMsg = std::string("exception: ") + e.what();
        return std::make_tuple(NCSI_LOG_ERR, NCSI_REQUESTER_SEND_FAIL,
                               returnMsg, 0);
    }

    return ncsiInfo;
}

int sendCommand(int eid, int package, int channel, int cmd,
                std::span<const unsigned char> payload, bool verbose)
{
    ReturnInfo ncsiInfo{};
    std::vector<uint8_t> responseMsg{};
    struct ncsi_rsp_pkt_hdr* responsePtr = nullptr;

    if (verbose)
    {
        std::ios_base::fmtflags f(std::cout.flags());
        std::cout << "Send NCSI Command, EID : " << std::hex << eid
                  << ", PACKAGE : " << std::hex << package
                  << ", CHANNEL : " << std::hex << channel
                  << ", COMMAND : " << std::hex << cmd << std::endl;
        std::cout.flags(f);
        if (!payload.empty())
        {
            std::cout << "PAYLOAD :";
            for (auto& i : payload)
            {
                std::cout << " " << std::hex << std::setfill('0')
                          << std::setw(2) << (int)i;
            }
            std::cout.flags(f);
            std::cout << std::endl;
        }
    }

    ncsiInfo = applyCmd(
        eid, Command(NcsiMctpCommands::NCSI_CMD_SEND_RAW_CMD, cmd, payload),
        responseMsg, package, channel, verbose);
    responsePtr =
        reinterpret_cast<struct ncsi_rsp_pkt_hdr*>(responseMsg.data());
    parseResponseMsg(responsePtr, ncsiInfo,
                     responseMsg.size() - sizeof(ncsi_pkt_hdr) -
                         sizeof(uint32_t));
    return std::get<1>(ncsiInfo);
}

} // namespace ncsi_mctp
} // namespace network
} // namespace phosphor
