#pragma once

#include <bitset>
#include <cstdint>

namespace phosphor
{
namespace network
{
namespace ncsi_mctp
{

constexpr size_t maxInstanceIds = 256;

/** @class InstanceId
 *  @brief Implementation of NCSI instance id
 */
class InstanceId
{
  public:
    /** @brief Get next unused instance id
     *  @return - NCSI instance id
     */
    uint8_t next();

    /** @brief Mark an instance id as unused
     *  @param[in] instanceId - NCSI instance id to be freed
     */
    void markFree(uint8_t instanceId)
    {
        id.set(instanceId, false);
    }

  private:
    std::bitset<maxInstanceIds> id;
};

} // namespace ncsi_mctp
} // namespace network
} // namespace phosphor
