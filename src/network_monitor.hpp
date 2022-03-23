#pragma once

#include <memory>
#include <string>
#include <variant>

#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>

namespace phosphor
{
namespace network
{

using propertyMapType = std::map<std::string, std::variant<std::string>>;

/** @class NetworkMonitor
 *  @brief Class implements the APIs required to fire network online target 
 *         based on properties observed on systemd networkd interface.
 */
class NetworkMonitor
{
  public:
    NetworkMonitor() = delete;
    NetworkMonitor(const NetworkMonitor&) = delete;
    NetworkMonitor& operator=(const NetworkMonitor&) = delete;
    NetworkMonitor(NetworkMonitor&&) = delete;
    NetworkMonitor& operator=(NetworkMonitor&&) = delete;
    virtual ~NetworkMonitor() = default;

    /** @brief Constructor
     *  @param[in] bus - sdbus reference.
     */
    NetworkMonitor(sdbusplus::bus::bus& bus);

  private:  
    /** @brief manages single registration for network interface
     *         property change 
     */    
    void registerSignalCallback();
    
    /** @brief Gets network interface properties to determine netwok
     *         online state   
     */    
    void checkNetworkStatus();

    /** @brief starts or stops the network online target 
     *  @param[in] start - bool to start/stop
     */        
    void manageNetworkTarget(bool start);

    /** @brief returns network online state  
     */
    bool getNtOnlineState();

    /** @brief Update the internal properties managed by the object
     *  @param[in] data - list of properties 
     */    
    void updateProperties(propertyMapType data);
    
    /** @brief last known network target online state */  
    sdbusplus::bus::bus& bus;
    
    /** @brief match exp for network interface property interface */  
    std::unique_ptr<sdbusplus::bus::match::match> networkInfMatch;

    /** @brief last known network target online state */  
    bool lastNtOnlineState;

    /** @brief network interface address state property */
    std::string addressState;

    /** @brief network interface online state property */
    std::string onlineState;

    /** @brief flag to manage the startup condition */
    bool startup;
};

} // namespace network
} // namespace phosphor