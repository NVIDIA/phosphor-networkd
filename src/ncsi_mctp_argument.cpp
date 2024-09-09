#include "ncsi_mctp_argument.hpp"

#include <algorithm>
#include <iostream>
#include <iterator>

namespace phosphor
{
namespace network
{
namespace ncsi_mctp
{

ArgumentParser::ArgumentParser(int argc, char** argv)
{
    int option = 0;
    while (-1 != (option = getopt_long(argc, argv, optionStr, options, NULL)))
    {
        if ((option == '?') || (option == 'h'))
        {
            usage(argv);
            exit(-1);
        }

        auto i = &options[0];
        while ((i->val != option) && (i->val != 0))
        {
            ++i;
        }

        if (i->val)
        {
            arguments[i->name] = (i->has_arg ? optarg : trueString);
        }
    }
}

const std::string& ArgumentParser::operator[](const std::string& opt)
{
    auto i = arguments.find(opt);
    if (i == arguments.end())
    {
        return emptyString;
    }
    else
    {
        return i->second;
    }
}

void ArgumentParser::usage(char** argv)
{
    std::cerr << "Usage: " << argv[0] << " [options]\n";
    std::cerr << "Options:\n";
    std::cerr << "    --help                   Print this menu.\n";
    std::cerr << "    --eid=<MCTP EID>         Specify a EID.\n";
    std::cerr << "    --package=<package>      Specify a package.\n";
    std::cerr << "    --channel=<channel>      Specify a channel.\n";
    std::cerr << "    --cmd=<cmd>              Specify a command of NCSI.\n";
    std::cerr
        << "    --payload=<hex data>     Specify the payload of NCSI command.\n";
    std::cerr
        << "    --verbose                Verbose output to see each packet transfers.\n";
    std::cerr << std::flush;
}

const option ArgumentParser::options[] = {
    {"eid", required_argument, NULL, 'e'},
    {"package", required_argument, NULL, 'p'},
    {"channel", required_argument, NULL, 'c'},
    {"cmd", required_argument, NULL, 'm'},
    {"payload", required_argument, NULL, 'o'},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0},
};

const char* ArgumentParser::optionStr = "e:p:c:m:o:v:h?";

const std::string ArgumentParser::trueString = "true";
const std::string ArgumentParser::emptyString = "";

} // namespace ncsi_mctp
} // namespace network
} // namespace phosphor
