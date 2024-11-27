/*
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "static_gateway.hpp"

#include "ethernet_interface.hpp"
#include "network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <string>
namespace phosphor
{
namespace network
{
static auto makeObjPath(std::string_view root, std::string addr)
{
    auto ret = sdbusplus::message::object_path(std::string(root));
    ret /= addr;
    return ret;
}
StaticGateway::StaticGateway(sdbusplus::bus_t& bus, std::string_view objRoot,
                             stdplus::PinnedRef<EthernetInterface> parent,
                             std::string gateway, IP::Protocol protocolType) :
    StaticGateway(bus, makeObjPath(objRoot, gateway), parent, gateway,
                  protocolType)
{}
StaticGateway::StaticGateway(sdbusplus::bus_t& bus,
                             sdbusplus::message::object_path objPath,
                             stdplus::PinnedRef<EthernetInterface> parent,
                             std::string gateway, IP::Protocol protocolType) :
    StaticGatewayObj(bus, objPath.str.c_str(),
                     StaticGatewayObj::action::defer_emit),
    parent(parent), objPath(std::move(objPath))
{
    StaticGatewayObj::gateway(gateway, true);
    StaticGatewayObj::protocolType(protocolType, true);
    emit_object_added();
}
void StaticGateway::delete_()
{
    auto& staticGateways = parent.get().staticGateways;
    std::unique_ptr<StaticGateway> ptr;
    for (auto it = staticGateways.begin(); it != staticGateways.end(); ++it)
    {
        if (it->second.get() == this)
        {
            ptr = std::move(it->second);
            staticGateways.erase(it);
            break;
        }
    }
    parent.get().writeConfigurationFile();
    parent.get().manager.get().reloadConfigs();
}
using sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using REASON =
    phosphor::logging::xyz::openbmc_project::Common::NotAllowed::REASON;
using phosphor::logging::elog;
std::string StaticGateway::gateway(std::string /*gateway*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}
IP::Protocol StaticGateway::protocolType(IP::Protocol /*protocolType*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}
} // namespace network
} // namespace phosphor
