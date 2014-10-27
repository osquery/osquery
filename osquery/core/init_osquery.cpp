// Copyright 2004-present Facebook. All Rights Reserved.

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/flags.h"
#include "osquery/filesystem.h"
#include "osquery/registry.h"

namespace osquery {


const std::string kDescription = "your operating system as a high-performance "
  "relational database";
const std::string kEpilog = "osquery project page <http://osquery.io>.";

DEFINE_osquery_flag(string,
                    osquery_log_dir,
                    "/var/log/osquery/",
                    "Directory to store results logging.")

static const char* basename(const char* filename) {
  const char* sep = strrchr(filename, '/');
  return sep ? sep + 1 : filename;
}

void initOsquery(int argc, char *argv[]) {
  std::string binary(basename(argv[0]));
  std::string first_arg = (argc > 1) ? std::string(argv[1]) : "";

  if (binary == "osqueryd" && (first_arg == "--help" || first_arg == "-h")) {
    // Parse help options before gflags. Only display osquery-related options.
    fprintf(stdout, "osquery " VERSION ", %s\n", kDescription.c_str());
    fprintf(stdout, "%s: [OPTION]...\n\n", binary.c_str());
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

  // Let gflags parse the non-help options/flags.
  google::ParseCommandLineNonHelpFlags(&argc, &argv, false);

  if (isWritable(FLAGS_osquery_log_dir.c_str()).ok()) {
    FLAGS_log_dir = FLAGS_osquery_log_dir;
  }

  google::InitGoogleLogging(argv[0]);
  osquery::InitRegistry::get().run();
}
}
