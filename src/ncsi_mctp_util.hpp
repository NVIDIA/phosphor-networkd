#pragma once

#include <span>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <variant>
#include <filesystem>
#include <map>
#include <bitset>
#include <sdbusplus/message/types.hpp>

#include "ncsi_mctp.hpp"

#define NCSI_PACKAGE_SHIFT	5
#define NCSI_TO_CHANNEL(p, c)	(((p) << NCSI_PACKAGE_SHIFT) | (c))

namespace phosphor
{
namespace network
{
namespace ncsi_mctp
{

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;

constexpr auto mapperService = "xyz.openbmc_project.ObjectMapper";
constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";

using ObjectPath = std::string;
using ServiceName = std::string;
using Interfaces = std::vector<std::string>;
using MapperServiceMap = std::vector<std::pair<ServiceName, Interfaces>>;
using GetSubTreeResponse = std::vector<std::pair<ObjectPath, MapperServiceMap>>;

using Interface = std::string;
using Property = std::string;
using Value =
    std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
                 uint64_t, double, std::string, std::vector<uint8_t>>;
using PropertyMap = std::map<Property, Value>;
using InterfaceMap = std::map<Interface, PropertyMap>;
using ObjectValueTree = std::map<sdbusplus::message::object_path, InterfaceMap>;

using ReturnMsg = std::string;
using ReturnData = int;
using ReturnInfo = std::tuple<ncsi_requester_log_level_t, ncsi_requester_rc_t, ReturnMsg, ReturnData>;

/** @struct CustomFD
 *
 *  RAII wrapper for file descriptor.
 */
struct CustomFD
{
    CustomFD(const CustomFD&) = delete;
    CustomFD& operator=(const CustomFD&) = delete;
    CustomFD(CustomFD&&) = delete;
    CustomFD& operator=(CustomFD&&) = delete;

    CustomFD(int fd) : fd(fd)
    {}

    ~CustomFD()
    {
        if (fd >= 0)
        {
            close(fd);
        }
    }

    int operator()() const
    {
        return fd;
    }

  private:
    int fd = -1;
};

class Command
{
  public:
    Command() = delete;
    ~Command() = default;
    Command(const Command&) = delete;
    Command& operator=(const Command&) = delete;
    Command(Command&&) = default;
    Command& operator=(Command&&) = default;
    Command(
        int c, int nc = DEFAULT_VALUE,
        std::span<const unsigned char> p = std::span<const unsigned char>()) :
        cmd(c),
        ncsi_cmd(nc), payload(p)
    {
    }

    int cmd;
    int ncsi_cmd;
    std::span<const unsigned char> payload;
};

/**
 * enum NcsiMctpCommands - specific NCSI commands
 *
 * @NCSI_CMD_UNSPEC: unspecified command to catch errors
 * @NCSI_CMD_SEND_RAW_CMD: specific NC-SI command id and payload to network card.
 * @NCSI_CMD_MAX: highest command number
 */
enum NcsiMctpCommands {
	NCSI_CMD_UNSPEC,
	NCSI_CMD_SEND_RAW_CMD,

	__NCSI_CMD_AFTER_LAST,
	NCSI_CMD_MAX = __NCSI_CMD_AFTER_LAST - 1
};

/** @brief Print the buffer if verbose is enabled
 *
 *  @param[in]  verbose - verbosity flag - true/false
 *  @param[in]  isTx - True if the buffer is an outgoing NCSI message, false if
                       the buffer is an incoming NCSI message
 *  @param[in]  buffer - Buffer to print
 *
 *  @return - None
 */
void printBuffer(bool verbose, bool isTx, const std::vector<uint8_t>& buffer);

/** @brief Implementation for RequesterIntf.GetInstanceId */
uint8_t getInstanceId(uint8_t eid);

/** @brief Mark an instance id as unused
*  @param[in] eid - MCTP eid to which this instance id belongs
*  @param[in] instanceId - NCSI instance id to be freed
*  @note will throw std::out_of_range if instanceId > 255
*/
void markFree(uint8_t eid, uint8_t instanceId);

/**
 *  @brief Get the Subtree response from the mapper
 *
 *  @param[in] searchPath - DBUS object path
 *  @param[in] depth - Search depth
 *  @param[in] ifaceList - list of the interface that are being
 *                         queried from the mapper
 *
 *  @return GetSubTreeResponse - the mapper subtree response
 *
 *  @throw sdbusplus::exception::exception when it fails
 */
GetSubTreeResponse getSubtree(const std::string& searchPath, int depth,
                              const std::vector<std::string>& ifaceList);

/** @brief Get MCTP demux daemon socket address
 *
 *  getMctpSockAddr does a D-Bus lookup for MCTP remote endpoint and return
 *  the unix socket info to be used for Tx/Rx
 *
 *  @param[in]  eid - Request MCTP endpoint
 *
 *  @return On success return the type, protocol and unit socket address, on
 *          failure the address will be empty
 */
std::tuple<int, int, std::vector<uint8_t>> getMctpSockInfo(uint8_t remoteEID);

/* @brief  This function will ask mctp helper function
 *         to send an NCSI command with the specified
 *         cmd number and payload as the data.
 *         This function talks with the helper functions.
 *
 * @param[in] eid     - EID of the mctp command.
 * @param[in] package - Package number.
 * @param[in] channel - Channel number with in the package.
 * @param[in] cmd     - Cmd number in NCSI spec.
 * @param[in] payload - Payload data to send.
 * @param[in] verbose - verbosity flag - true/false
 *
 * @returns 0 on success and negative value for failure.
 */
int sendCommand(int eid, int package, int channel, int cmd,
                   std::span<const unsigned char> payload, bool verbose);

/** @brief print the input message if verbose is enabled
 *
 *  @param[in]  verbose - verbosity flag - true/false
 *  @param[in]  msg     - message to print
 *  @param[in]  data    - return data to print
 *
 *  @return - None
 */
template <class T>
void logger(bool verbose, std::string msg, const T& data)
{
    if (verbose) {
        std::stringstream s;
        s << data;
        std::cout << "ncsi-mctp: " << msg.c_str() << ", RC = " << s.str() << std::endl;
    }
}

} // namespace ncsi_mctp
} // namespace network
} // namespace phosphor
