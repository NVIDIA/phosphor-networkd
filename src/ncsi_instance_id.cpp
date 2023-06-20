#include "ncsi_instance_id.hpp"

#include <stdexcept>

namespace phosphor
{
namespace network
{
namespace ncsi_mctp
{

uint8_t InstanceId::next()
{
    /* NCSI IID numbers are 8-bit values that shall range from 0x01 to 0xFF */
    uint8_t idx = 1;
    while (idx < id.size() && id.test(idx))
    {
        ++idx;
    }

    if (idx == id.size())
    {
        throw std::runtime_error("No free instance ids");
    }

    id.set(idx);
    return idx;
}

} // namespace ncsi_mctp
} // namespace network
} // namespace phosphor
