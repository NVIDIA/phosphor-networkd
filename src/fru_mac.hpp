#pragma once

#include <sdbusplus/bus.hpp>
#include <stdplus/pinned.hpp>

#include <memory>

namespace phosphor::network
{

class Manager;

namespace fru
{

struct Runtime
{
    virtual ~Runtime() = default;
};

/** @brief Read the MAC address from a FRU EEPROM and apply it to the
 *         configured network interface via the network Manager.
 *
 *  The EEPROM path and target interface name are read from the JSON config
 *  installed at /usr/share/phosphor-network/fru-mac.json:
 *    { "eeprom": "/sys/class/i2c-dev/i2c-10/device/10-0050/eeprom",
 *      "interface": "eth0" }
 *
 *  Enabled at build time with -Dfru-mac=enabled.
 */
std::unique_ptr<Runtime> watch(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                               stdplus::PinnedRef<Manager> m);

} // namespace fru
} // namespace phosphor::network
