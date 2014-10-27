// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/flags.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/registry.h"

namespace osquery {

const std::string kDefaultLogDir = "/var/log/osquery/";
const std::string kDescription = "your operating system as a high-performance "
  "relational database";
const std::string kEpilog = "osquery project page <http://osquery.io>.";

static const char* basename(const char* filename) {
  const char* sep = strrchr(filename, '/');
  return sep ? sep + 1 : filename;
}

void initOsquery(int argc, char *argv[]) {
  if (argc > 1 && (std::string(argv[1]) == "--help" ||
      std::string(argv[1]) == "-h")) {
    // Parse help options before gflags. Only display osquery-related options.
    fprintf(stdout, "osquery " VERSION ", %s\n", kDescription.c_str());
    fprintf(stdout, "%s: [OPTION]...\n\n", basename(argv[0]));
    fprintf(stdout, "The following options control the osquery "
      "daemon and shell.\n\n");

    auto flags = Flag::get().flags();
    for (auto& flag : flags) {
      fprintf(stdout, "  --%s, --%s=VALUE\n    %s (default: %s)\n",
        flag.first.c_str(), flag.first.c_str(), flag.second.second.c_str(),
        flag.second.first.c_str());
    }
    fprintf(stdout, "\n%s\n", kEpilog.c_str());

    ::exit(0);
  }

  FLAGS_alsologtostderr = true;
  FLAGS_logbufsecs = 0; // flush the log buffer immediately
  FLAGS_stop_logging_if_full_disk = true;
  FLAGS_max_log_size = 1024; // max size for individual log file is 1GB
  if (access(kDefaultLogDir.c_str(), W_OK) == 0) {
    FLAGS_log_dir = kDefaultLogDir;
  }

  google::InitGoogleLogging(argv[0]);
  osquery::InitRegistry::get().run();

  try {
    DBHandle::getInstance();
  } catch (std::exception& e) {
    LOG(ERROR) << "osquery failed to start: " << e.what();
    ::exit(1);
  }

  // Let gflags parse the non-help options/flags.
  google::ParseCommandLineNonHelpFlags(&argc, &argv, true);
}
}
