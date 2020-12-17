#include "config.h"

#include "network_config.hpp"

#include <fstream>
#include <string>

namespace phosphor
{
namespace network
{

namespace bmc
{
void writeDHCPDefault(const std::string& filename, const std::string& interface)
{
    std::ofstream filestream;

    filestream.open(filename);
    filestream << "[Match]\nName=" << interface <<
                "\n[Network]\nDHCP=true\n"
#ifdef LINK_LOCAL_AUTOCONFIGURATION
                "LinkLocalAddressing=yes\n"
#else
                "LinkLocalAddressing=no\n"
#endif
#ifdef IPV6_ACCEPT_RA
                "IPv6AcceptRA=true\n"
#else
                "IPv6AcceptRA=false\n"
#endif
                "[DHCP]\nClientIdentifier=mac\n";
    filestream.close();
}
} // namespace bmc

} // namespace network
} // namespace phosphor
