#include "test_network_manager.hpp"

#include "config_parser.hpp"

#include <net/if_arp.h>

#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>

#include <filesystem>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using ::testing::Key;
using ::testing::UnorderedElementsAre;

class TestNetworkManager : public stdplus::gtest::TestWithTmp
{
  protected:
    stdplus::Pinned<sdbusplus::bus_t> bus;
    TestManager manager;
    TestNetworkManager() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, "/xyz/openbmc_test/abc", CaseTmpDir())
    {}

    void deleteVLAN(std::string_view ifname)
    {
        manager.interfaces.find(ifname)->second->vlan->delete_();
    }
};

TEST_F(TestNetworkManager, NoInterface)
{
    EXPECT_TRUE(manager.interfaces.empty());
}

TEST_F(TestNetworkManager, WithSingleInterfaceOperStateAfterAdd)
{
    // Netlink reports the new link first.
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 2, .flags = 0, .name = "igb1"});
    EXPECT_TRUE(manager.interfaces.empty());

    // systemd-networkd then publishes the link's operational state.
    manager.handleOperState("routable", 2);
    EXPECT_THAT(manager.interfaces, UnorderedElementsAre(Key("igb1")));
}

TEST_F(TestNetworkManager, WithSingleInterfaceOperStateBeforeAdd)
{
    // systemd-networkd publishes an operational state for a link the manager
    // has not yet been told about.
    manager.handleOperState("routable", 2);
    EXPECT_TRUE(manager.interfaces.empty());

    // Netlink subsequently reports the matching link.
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 2, .flags = 0, .name = "igb1"});
    EXPECT_THAT(manager.interfaces, UnorderedElementsAre(Key("igb1")));
}

TEST_F(TestNetworkManager, WithMultipleInterfaces)
{
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "igb0"});
    manager.handleOperState("routable", 1);
    manager.handleOperState("off", 2);
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 2, .flags = 0, .name = "igb1"});

    EXPECT_THAT(manager.interfaces,
                UnorderedElementsAre(Key("igb0"), Key("igb1")));
}

TEST_F(TestNetworkManager, NICEnabledTrueWhenOperStateRoutable)
{
    manager.handleOperState("routable", 1);
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "eth0"});
    auto it = manager.interfaces.find("eth0");
    ASSERT_NE(it, manager.interfaces.end());
    EXPECT_TRUE(it->second->nicEnabled());
}

TEST_F(TestNetworkManager, NICEnabledFalseWhenOperStateOff)
{
    manager.handleOperState("off", 1);
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "eth0"});
    auto it = manager.interfaces.find("eth0");
    ASSERT_NE(it, manager.interfaces.end());
    EXPECT_FALSE(it->second->nicEnabled());
}

TEST_F(TestNetworkManager, NICEnabledTrueForNonOffOperStates)
{
    constexpr std::string_view states[] = {
        "no-carrier", "dormant",  "degraded-carrier",
        "carrier",    "degraded", "enslaved"};
    unsigned idx = 1;
    for (const auto& state : states)
    {
        manager.handleOperState(state, idx);
        std::string name = "eth" + std::to_string(idx);
        manager.addInterface(
            {.type = ARPHRD_ETHER, .idx = idx, .flags = 0, .name = name});
        auto it = manager.interfaces.find(name);
        ASSERT_NE(it, manager.interfaces.end()) << "state=" << state;
        EXPECT_TRUE(it->second->nicEnabled()) << "state=" << state;
        ++idx;
    }
}

TEST_F(TestNetworkManager, NICEnabledTracksOperStateChanges)
{
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "eth0"});
    manager.handleOperState("routable", 1);
    auto it = manager.interfaces.find("eth0");
    ASSERT_NE(it, manager.interfaces.end());
    EXPECT_TRUE(it->second->nicEnabled());

    // Live OperationalState transitions must drive NICEnabled without going
    // through the override (no config-file write or networkd reload). The
    // test fixture does not expect any reload schedule() calls.
    manager.handleOperState("off", 1);
    EXPECT_FALSE(it->second->nicEnabled());

    manager.handleOperState("routable", 1);
    EXPECT_TRUE(it->second->nicEnabled());
}

TEST_F(TestNetworkManager, OperStateClearedOnRemove)
{
    manager.handleOperState("routable", 1);
    InterfaceInfo info{
        .type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "eth0"};
    manager.addInterface(info);
    ASSERT_NE(manager.interfaces.find("eth0"), manager.interfaces.end());

    manager.removeInterface(info);
    EXPECT_TRUE(manager.interfaces.empty());

    // Re-adding the same ifidx without a fresh handleOperState must NOT
    // produce an interface, proving the cached operstate was cleared.
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "eth1"});
    EXPECT_TRUE(manager.interfaces.empty());
}

TEST_F(TestNetworkManager, WithVLAN)
{
    EXPECT_THROW(manager.vlan("", 8000), std::exception);
    EXPECT_THROW(manager.vlan("", 0), std::exception);
    EXPECT_THROW(manager.vlan("eth0", 2), std::exception);

    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "eth0"});
    manager.handleOperState("routable", 1);
    EXPECT_NO_THROW(manager.vlan("eth0", 2));
    EXPECT_NO_THROW(manager.vlan("eth0", 4094));
    EXPECT_THAT(
        manager.interfaces,
        UnorderedElementsAre(Key("eth0"), Key("eth0.2"), Key("eth0.4094")));
    auto netdev1 = config::pathForIntfDev(CaseTmpDir(), "eth0.2");
    auto netdev2 = config::pathForIntfDev(CaseTmpDir(), "eth0.4094");
    EXPECT_TRUE(std::filesystem::is_regular_file(netdev1));
    EXPECT_TRUE(std::filesystem::is_regular_file(netdev2));

    deleteVLAN("eth0.2");
    EXPECT_THAT(manager.interfaces,
                UnorderedElementsAre(Key("eth0"), Key("eth0.4094")));
    EXPECT_FALSE(std::filesystem::is_regular_file(netdev1));
    EXPECT_TRUE(std::filesystem::is_regular_file(netdev2));
}

} // namespace network
} // namespace phosphor
