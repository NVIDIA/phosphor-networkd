#include "network_monitor.hpp"

#include <stdlib.h>

#include <sdbusplus/test/sdbus_mock.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::StrEq;

class TestNetworkMonitor : public testing::Test
{
  public:
    sdbusplus::SdBusMock sdbus_mock;
    sdbusplus::bus::bus bus;

    TestNetworkMonitor() : bus(sdbusplus::get_mocked_new(&sdbus_mock)) {}

    ~TestNetworkMonitor() {}
};

TEST_F(TestNetworkMonitor, StartOnlineTargetTest)
{
    EXPECT_CALL(sdbus_mock,
                sd_bus_message_new_method_call(
                    IsNull(), _, StrEq("org.freedesktop.network1"),
                    StrEq("/org/freedesktop/network1"), _, StrEq("GetAll")))
        .WillOnce(Return(0));

    /*
        If routable link is found network target must be started
        AddressState = routable and OnlineState = online/partial
    */
    EXPECT_CALL(sdbus_mock,
                sd_bus_message_new_method_call(
                    IsNull(), _, StrEq("org.freedesktop.systemd1"),
                    StrEq("/org/freedesktop/systemd1"), _, StrEq("StartUnit")))
        .WillOnce(Return(0));

    EXPECT_CALL(sdbus_mock, sd_bus_message_read_basic(IsNull(), 's', NotNull()))
        .WillOnce(Invoke([&](sd_bus_message* m, char type, void* p) {
        const char** s = static_cast<const char**>(p);
        (void)m;
        (void)type;
        *s = "AddressState";
        return 0;
    }))
        .WillOnce(Invoke([&](sd_bus_message* m, char type, void* p) {
        const char** s = static_cast<const char**>(p);
        (void)m;
        (void)type;
        *s = "routable";
        return 0;
    }))
        .WillOnce(Invoke([&](sd_bus_message* m, char type, void* p) {
        const char** s = static_cast<const char**>(p);
        (void)m;
        (void)type;
        *s = "OnlineState";
        return 0;
    })).WillOnce(Invoke([&](sd_bus_message* m, char type, void* p) {
        const char** s = static_cast<const char**>(p);
        (void)m;
        (void)type;
        *s = "partial";
        return 0;
    }));

    // while !at_end()
    EXPECT_CALL(sdbus_mock, sd_bus_message_at_end(IsNull(), 0))
        .WillOnce(Return(0))
        .WillOnce(Return(0))
        .WillOnce(Return(1)); // So it exits the loop after reading two pair.

    EXPECT_CALL(sdbus_mock,
                sd_bus_message_verify_type(IsNull(), 'v', StrEq("s")))
        .WillOnce(Return(1))
        .WillOnce(Return(1));

    NetworkMonitor NtMonitor(bus);
}

TEST_F(TestNetworkMonitor, StopOnlineTargetTest)
{
    EXPECT_CALL(sdbus_mock,
                sd_bus_message_new_method_call(
                    IsNull(), _, StrEq("org.freedesktop.network1"),
                    StrEq("/org/freedesktop/network1"), _, StrEq("GetAll")))
        .WillOnce(Return(0));

    /*
        If routable link is not found network target must not be started
        AddressState != routable or OnlineState = online/partial
    */
    EXPECT_CALL(sdbus_mock,
                sd_bus_message_new_method_call(
                    IsNull(), _, StrEq("org.freedesktop.systemd1"),
                    StrEq("/org/freedesktop/systemd1"), _, StrEq("StopUnit")))
        .WillOnce(Return(0));

    EXPECT_CALL(sdbus_mock, sd_bus_message_read_basic(IsNull(), 's', NotNull()))
        .WillOnce(Invoke([&](sd_bus_message* m, char type, void* p) {
        const char** s = static_cast<const char**>(p);
        (void)m;
        (void)type;
        *s = "AddressState";
        return 0;
    }))
        .WillOnce(Invoke([&](sd_bus_message* m, char type, void* p) {
        const char** s = static_cast<const char**>(p);
        (void)m;
        (void)type;
        *s = "degraded";
        return 0;
    }))
        .WillOnce(Invoke([&](sd_bus_message* m, char type, void* p) {
        const char** s = static_cast<const char**>(p);
        (void)m;
        (void)type;
        *s = "OnlineState";
        return 0;
    })).WillOnce(Invoke([&](sd_bus_message* m, char type, void* p) {
        const char** s = static_cast<const char**>(p);
        (void)m;
        (void)type;
        *s = "offline";
        return 0;
    }));

    // while !at_end()
    EXPECT_CALL(sdbus_mock, sd_bus_message_at_end(IsNull(), 0))
        .WillOnce(Return(0))
        .WillOnce(Return(0))
        .WillOnce(Return(1)); // So it exits the loop after reading two pair.

    EXPECT_CALL(sdbus_mock,
                sd_bus_message_verify_type(IsNull(), 'v', StrEq("s")))
        .WillOnce(Return(1))
        .WillOnce(Return(1));

    NetworkMonitor NtMonitor(bus);
}

} // namespace network
} // namespace phosphor
