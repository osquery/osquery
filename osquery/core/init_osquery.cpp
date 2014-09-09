// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <boost/algorithm/string/predicate.hpp>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/registry.h"

using namespace boost::algorithm;

namespace osquery {
namespace core {

const std::string kDefaultHelp = R"(
  osquery
    --help, -h        print help message
)";

const std::string kOsquerydHelp = R"(
  osqueryd
    --help, -h            Print help and usage information

    --config_retriever    The config plugin to use (ex: filesystem, http)
                            Default: filesystem

    --config_path         If using the filesystem config plugin, the path where
                          your osquery JSON config file can be found
                            Default: /var/osquery/osquery.conf

    --log_receiver        The logger plugin to use (ex: filesystem, scribe)
                            Default: filesystem

    --log_dir             The directory which you would like to store your
                          output logs
                            Default: /var/log/osquery/

    -v                    Increase output verbosity
                            Example: -v=3
)";

const std::map<std::string, std::string> kHelpMessages = {
    {"osqueryd", kOsquerydHelp}, };

const std::string kDefaultLogDir = "/var/log/osquery/";

char *stringToChar(const std::string &s) {
  char *pc = new char[s.size() + 1];
  std::strcpy(pc, s.c_str());
  return pc;
}

void printHelp(char *argv0) {
  auto bits = split(std::string(argv0), "/");
  auto program_name = bits[bits.size() - 1];
  for (const auto &it : kHelpMessages) {
    if (it.first == program_name) {
      std::cout << it.second << std::endl;
      return;
    }
  }
  // this should only be reached if the binary name didn't match any of the
  // presets
  std::cout << kDefaultHelp << std::endl;
}

void printHelpAndExit(char *argv0, int code) {
  printHelp(argv0);
  exit(code);
}

// gflags help is pretty ugly, so let's intercept calls to "--help" and the
// like so that we can proactively print prettier help messages
std::pair<int, char **> parseCommandLineFlags(int argc, char **argv) {
  std::vector<std::string> new_args;
  for (int i = 0; i < argc; ++i) {
    std::string arg(argv[i]);
    if (contains(arg, "help")) {
      // this will match "--help", "-help", "help" and pretty much every string
      // that has the word "help" in it. beware of this if you try to create
      // and argument called something like "--foo-help"
      printHelpAndExit(argv[0], 0);
    } else if (starts_with(arg, "-") && ends_with(arg, "-h")) {
      // this will match "-h" and "--h", but be aware that it was also match
      // args like "--foo-h"
      printHelpAndExit(argv[0], 0);
    } else {
      // the argument wasn't a flag that we want to intercept, so pass it to
      // glog
      new_args.push_back(arg);
    }
  }

  int new_argc = (int)new_args.size();
  std::vector<char *> char_vector;
  std::transform(new_args.begin(),
                 new_args.end(),
                 std::back_inserter(char_vector),
                 stringToChar);
  char **new_argv = (char **)new char(new_argc + 1);
  for (int i = 0; i < char_vector.size(); ++i) {
    new_argv[i] = char_vector[i];
  }
  return std::make_pair(new_argc, new_argv);
}

void initOsquery(int argc, char *argv[]) {
  FLAGS_alsologtostderr = true;
  FLAGS_logbufsecs = 0; // flush the log buffer immediately
  FLAGS_stop_logging_if_full_disk = true;
  FLAGS_max_log_size = 1024; // max size for individual log file is 1GB
  FLAGS_log_dir = kDefaultLogDir;
  google::InitGoogleLogging(argv[0]);
  osquery::InitRegistry::get().run();
  auto new_args = osquery::core::parseCommandLineFlags(argc, argv);
  google::ParseCommandLineFlags(&new_args.first, &new_args.second, true);
}
}
}
