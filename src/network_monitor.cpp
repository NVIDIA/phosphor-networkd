
#include "network_monitor.hpp"

#include <fmt/core.h>

#include <phosphor-logging/log.hpp>

namespace phosphor
{
namespace network
{

using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;

NetworkMonitor::NetworkMonitor(sdbusplus::bus::bus& bus) : bus(bus)
{
    startup = true;
    lastNtOnlineState = false;
    registerSignalCallback();
    checkNetworkStatus();
    startup = false;
}

void NetworkMonitor::registerSignalCallback()
{
    auto callback = [&](sdbusplus::message::message& m) {
        log<level::DEBUG>("Netwrok PropertiesChanged callback triggered");

        propertyMapType result;
        std::string path;
        m.read(path, result);

        if (!result.empty())
        {
            updateProperties(std::move(result));
        }
        else
        {
            log<level::ERR>(
                "Error in PropertiesChanged callback property read");
        }
    };

    networkInfMatch = std::make_unique<sdbusplus::bus::match::match>(
        bus,
        "interface='org.freedesktop.DBus.Properties',type='signal',"
        "member='PropertiesChanged',path='/org/freedesktop/network1'",
        callback);
}

bool NetworkMonitor::getNtOnlineState()
{
    return (addressState == "routable" &&
            (onlineState == "online" || onlineState == "partial"))
               ? true
               : false;
}

void NetworkMonitor::checkNetworkStatus()
{
    auto method = bus.new_method_call(
        "org.freedesktop.network1", "/org/freedesktop/network1",
        "org.freedesktop.DBus.Properties", "GetAll");
    method.append("org.freedesktop.network1.Manager");

    try
    {
        auto response = bus.call(method);
        if (response.is_method_error())
        {
            log<level::ERR>(
                "Error calling GetAll method of systemD network interface");
        }
        else
        {
            propertyMapType result;
            response.read(result);
            if (result.empty())
            {
                log<level::ERR>("Error in network1.Manager GetAll method call");
            }
            else
            {
                updateProperties(std::move(result));
            }
        }
    }
    catch (const sdbusplus::exception::exception& e)
    {
        log<level::ERR>(
            fmt::format("Error in network manager property get call: {}",
                        e.what())
                .c_str());
    }
}

void NetworkMonitor::manageNetworkTarget(bool start)
{
    std::string api = start ? "StartUnit" : "StopUnit";

    auto method = bus.new_method_call(
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", api.c_str());
    method.append("bmc-network-online.target", "replace");

    try
    {
        bus.call(method);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        log<level::ERR>(
            fmt::format("Error in target Start/Stop  call: {}", e.what())
                .c_str());
    }
}

void NetworkMonitor::updateProperties(propertyMapType data)
{
    for (auto property : data)
    {
        if (property.first == "AddressState")
        {
            addressState = std::get<std::string>(property.second);
        }
        if (property.first == "OnlineState")
        {
            onlineState = std::get<std::string>(property.second);
        }
    }

    if (lastNtOnlineState != getNtOnlineState() || startup)
    {
        lastNtOnlineState = getNtOnlineState();
        log<level::INFO>(
            fmt::format("Network property change detected"
                        "AddressState({}), OnlineState({}), NtOnlineState({})",
                        addressState, onlineState, lastNtOnlineState)
                .c_str());
        manageNetworkTarget(lastNtOnlineState);
    }
}

} // namespace network
} // namespace phosphor
