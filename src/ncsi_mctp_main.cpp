#include "ncsi_mctp_argument.hpp"
#include "ncsi_mctp_util.hpp"
#include "ncsi_mctp.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <bit>


static void exitWithError(const char* err, char** argv)
{
    phosphor::network::ncsi_mctp::ArgumentParser::usage(argv);
    std::cerr << "ERROR: " << err << "\n";
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    using namespace phosphor::network;
    using namespace phosphor::network::ncsi_mctp;
    // Read arguments.
    auto options = ArgumentParser(argc, argv);
    int eidInt{};
    int packageInt{};
    int channelInt{};
    int cmdInt{};
    bool verbose = false;
    std::vector<unsigned char> payload{};

    // Parse out eid argument.
    auto eid = (options)["eid"];
    try {
        eidInt = stoi(eid, nullptr);
    }
    catch (const std::exception& e) {
        exitWithError("EID not specified.", argv);
    }
    if (eidInt < 0) {
        exitWithError("EID value should be greater than or equal to 0",
                      argv);
    }

    // Parse out package argument.
    auto package = (options)["package"];
    try {
        packageInt = stoi(package, nullptr);
    }
    catch (const std::exception& e) {
        exitWithError("package not specified.", argv);
    }
    if (packageInt < 0) {
        exitWithError("package value should be greater than or equal to 0",
                      argv);
    }
    if (packageInt > 7) {
        exitWithError("package value should be less than or equal to 7",
                      argv);
    }

    // Parse out channel argument.
    auto channel = (options)["channel"];
    try {
        channelInt = stoi(channel, nullptr);
    }
    catch (const std::exception& e) {
        exitWithError("channel not specified.", argv);
    }
    if (channelInt < 0) {
        exitWithError("channel value should be greater than or equal to 0",
                      argv);
    }
    if (channelInt >31) {
        exitWithError("channel value should be less than or equal to 31",
                      argv);
    }

    // Parse out cmd argument.
    auto cmd = (options)["cmd"];
    try {
        cmdInt = stoi(cmd, nullptr);
    }
    catch (const std::exception& e) {
        exitWithError("cmd not specified.", argv);
    }
    if (cmdInt < 0) {
        exitWithError("cmd value should be greater than or equal to 0",
                      argv);
    }
    if (cmdInt > 96) {
        exitWithError("cmd value should be less than or equal to 96",
                      argv);
    }

    if ((options)["verbose"] == "true") {
        verbose = true;
    }

    auto payloadStr = (options)["payload"];
    if (!payloadStr.empty()) {
        std::string byte(2, '\0');
        if (payloadStr.size() % 2)
            exitWithError("Payload invalid: specify two hex digits per byte.",
                          argv);
        // Parse the payload string (e.g. "0000811900000000") to byte data
        for (unsigned int i = 1; i < payloadStr.size(); i += 2) {
            byte[0] = payloadStr[i - 1];
            byte[1] = payloadStr[i];
            try {
                payload.push_back(stoi(byte, nullptr, 16));
            }
            catch (const std::exception& e) {
                exitWithError("Payload invalid.", argv);
            }
        }
        if (payload.empty()) {
            exitWithError("No payload specified.", argv);
        }
    } else {
        if (cmdInt == NCSI_PKT_CMD_OEM) {
            exitWithError("No OEM payload specified", argv);
        }
    }

    return ncsi_mctp::sendCommand(
            eidInt, packageInt, channelInt, cmdInt,
            std::span<const unsigned char>(payload.begin(), payload.end()),
            verbose);
}
