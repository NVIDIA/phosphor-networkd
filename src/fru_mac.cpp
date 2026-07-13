#include "fru_mac.hpp"

#include "network_manager.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace phosphor::network::fru
{

constexpr auto configFile = "/usr/share/phosphor-network/fru-mac.json";

/** Parse a MAC address from raw FRU EEPROM bytes.
 *
 *  The FRU board area stores the MAC as a printable ASCII field prefixed with
 *  the text "MAC", e.g. "...MAC:AA:BB:CC:DD:EE:FF...".  Non-printable bytes
 *  between the label and the value are treated as whitespace.
 *
 *  Returns a string in "XX:XX:XX:XX:XX:XX" format.
 */
static std::string parseMac(const std::vector<uint8_t>& data)
{
    // Replace non-printable bytes with spaces for easier searching. Do not
    // strip the spaces — doing so would collapse a non-printable separator
    // (e.g. '\0') into the MAC value and shift the extraction offset.
    std::string text;
    text.reserve(data.size());
    for (uint8_t b : data)
    {
        text += (b >= 0x20 && b < 0x7f) ? static_cast<char>(b) : ' ';
    }

    constexpr std::string_view label = "MAC";
    auto pos = text.find(label);
    if (pos == std::string::npos)
    {
        throw std::runtime_error("MAC label not found in FRU EEPROM data");
    }

    // Skip the label and any separator/whitespace characters that follow.
    pos += label.size();
    while (pos < text.size() && (text[pos] == ':' || text[pos] == ' '))
    {
        ++pos;
    }

    constexpr std::size_t macLen = 17; // "XX:XX:XX:XX:XX:XX"
    if (pos + macLen > text.size())
    {
        throw std::runtime_error("MAC address field truncated in FRU EEPROM");
    }

    return text.substr(pos, macLen);
}

std::unique_ptr<Runtime> watch(stdplus::PinnedRef<sdbusplus::bus_t> /*bus*/,
                               stdplus::PinnedRef<Manager> m)
{
    // Read platform config: EEPROM path + target interface name.
    std::ifstream cfgStream(configFile);
    if (!cfgStream)
    {
        lg2::error("fru-mac: config not found at {PATH}", "PATH", configFile);
        return nullptr;
    }

    nlohmann::json cfg;
    try
    {
        cfgStream >> cfg;
    }
    catch (const std::exception& e)
    {
        lg2::error("fru-mac: failed to parse {PATH}: {ERR}", "PATH", configFile,
                   "ERR", e.what());
        return nullptr;
    }

    std::string eepromPath;
    std::string ifaceName;
    try
    {
        eepromPath = cfg.at("eeprom");
        ifaceName = cfg.at("interface");
    }
    catch (const nlohmann::json::exception& e)
    {
        lg2::error("fru-mac: missing required key in {PATH}: {ERR}", "PATH",
                   configFile, "ERR", e.what());
        return nullptr;
    }

    try
    {
        std::ifstream eeprom(eepromPath, std::ios::binary);
        if (!eeprom)
        {
            throw std::runtime_error("Cannot open EEPROM: " + eepromPath);
        }
        const std::vector<uint8_t> data(std::istreambuf_iterator<char>(eeprom),
                                        {});

        const auto mac = parseMac(data);
        lg2::info("fru-mac: applying MAC {MAC} to interface {INTF}", "MAC", mac,
                  "INTF", ifaceName);

        bool found = false;
        for (const auto& [name, iface] : m.get().interfaces)
        {
            if (name == ifaceName)
            {
                iface->macAddress(mac);
                found = true;
                break;
            }
        }
        if (!found)
        {
            lg2::warning("fru-mac: configured interface {INTF} not found",
                         "INTF", ifaceName);
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("fru-mac: {ERR}", "ERR", e.what());
    }

    return nullptr;
}

} // namespace phosphor::network::fru
