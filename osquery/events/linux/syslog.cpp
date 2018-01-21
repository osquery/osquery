/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <fcntl.h>
#include <grp.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <istream>
#include <string>

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/tokenizer.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

#include "osquery/events/linux/syslog.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

FLAG(bool, enable_syslog, false, "Enable the syslog ingestion event publisher");

FLAG(string,
     syslog_pipe_path,
     "/var/osquery/syslog_pipe",
     "Path to the named pipe used for forwarding rsyslog events");

FLAG(uint64,
     syslog_rate_limit,
     100,
     "Maximum number of logs to ingest per run (~200ms between runs)");

REGISTER(SyslogEventPublisher, "event_publisher", "syslog");

// rsyslog needs read/write access, osquery process needs read access
const mode_t kPipeMode = 0460;
const std::string kPipeGroupName = "syslog";
const char* kTimeFormat = "%Y-%m-%dT%H:%M:%S";
const std::vector<std::string> kCsvFields = {
    "time", "host", "severity", "facility", "tag", "message"};
const size_t kErrorThreshold = 10;

Status SyslogEventPublisher::setUp() {
  if (!FLAGS_enable_syslog) {
    return Status(1, "Publisher disabled via configuration");
  }

  Status s;
  if (!pathExists(FLAGS_syslog_pipe_path)) {
    VLOG(1) << "Pipe does not exist: creating pipe " << FLAGS_syslog_pipe_path;
    s = createPipe(FLAGS_syslog_pipe_path);
    if (!s.ok()) {
      LOG(WARNING) << RLOG(1964)
                   << "Problems encountered creating pipe: " << s.getMessage();
    }
  }

  fs::file_status file_status = fs::status(FLAGS_syslog_pipe_path);
  if (file_status.type() != fs::fifo_file) {
    return Status(1, "Not a FIFO file: " + FLAGS_syslog_pipe_path);
  }

  // Try to acquire a lock on the pipe, to make sure we're the only osquery
  // related proccess reading from it.
  s = lockPipe(FLAGS_syslog_pipe_path);
  if (!s.ok()) {
    return s;
  }

  // Opening with both flags appears to be the only way to open the pipe
  // without blocking for a writer. We won't ever write to the pipe, but we
  // don't want to block here and will instead block waiting for a read in the
  // run() method
  readStream_.open(FLAGS_syslog_pipe_path,
                   std::ifstream::in | std::ifstream::out);
  if (!readStream_.good()) {
    return Status(1,
                  "Error opening pipe for reading: " + FLAGS_syslog_pipe_path);
  }
  VLOG(1) << "Successfully opened pipe for syslog ingestion: "
          << FLAGS_syslog_pipe_path;

  return Status(0, "OK");
}

Status SyslogEventPublisher::createPipe(const std::string& path) {
  if (mkfifo(FLAGS_syslog_pipe_path.c_str(), kPipeMode) != 0) {
    return Status(1, "Error in mkfifo: " + std::string(strerror(errno)));
  }

  // Explicitly set the permissions since the umask will effect the
  // permissions created by mkfifo
  if (chmod(FLAGS_syslog_pipe_path.c_str(), kPipeMode) != 0) {
    return Status(1, "Error in chmod: " + std::string(strerror(errno)));
  }

  // Try to set the group so that rsyslog will be able to write to the pipe
  struct group* group = getgrnam(kPipeGroupName.c_str());
  if (group == nullptr) {
    VLOG(1) << "No group " << kPipeGroupName
            << " found. Not changing group for the pipe.";
    return Status(0, "OK");
  }
  if (chown(FLAGS_syslog_pipe_path.c_str(), -1, group->gr_gid) == -1) {
    return Status(1,
                  "Error in chown to group " + kPipeGroupName + ": " +
                      std::string(strerror(errno)));
  }
  return Status(0, "OK");
}

Status SyslogEventPublisher::lockPipe(const std::string& path) {
  lockFd_ = open(path.c_str(), O_NONBLOCK);
  if (lockFd_ == -1) {
    return Status(
        1, "Error in open for locking pipe: " + std::string(strerror(errno)));
  }
  if (flock(lockFd_, LOCK_EX | LOCK_NB) != 0) {
    lockFd_ = -1;
    return Status(
        1, "Unable to acquire pipe lock: " + std::string(strerror(errno)));
  }
  return Status(0, "OK");
}

void SyslogEventPublisher::unlockPipe() {
  if (lockFd_ != -1) {
    if (flock(lockFd_, LOCK_UN) != 0) {
      LOG(WARNING) << "Error unlocking pipe: " << std::string(strerror(errno));
    }
  }
}

Status SyslogEventPublisher::run() {
  // This run function will be called by the event factory with ~100ms pause
  // (see InterruptableRunnable::pause()) between runs. In case something goes
  // weird and there is a huge amount of input, we limit how many logs we
  // take in per run to avoid pegging the CPU.
  for (size_t i = 0; i < FLAGS_syslog_rate_limit; ++i) {
    if (readStream_.rdbuf()->in_avail() == 0) {
      // If there is no pending data, we have flushed everything and can wait
      // until the next time EventFactory calls run(). This also allows the
      // thread to join when it is stopped by EventFactory.
      return Status(0, "OK");
    }
    std::string line;
    std::getline(readStream_, line);
    auto ec = createEventContext();
    Status status = populateEventContext(line, ec);
    if (status.ok()) {
      fire(ec);
      if (errorCount_ > 0) {
        --errorCount_;
      }
    } else {
      LOG(ERROR) << status.getMessage() << " in line: " << line;
      ++errorCount_;
      if (errorCount_ >= kErrorThreshold) {
        return Status(1, "Too many errors in syslog parsing.");
      }
    }
  }
  return Status(0, "OK");
}

void SyslogEventPublisher::tearDown() {
  unlockPipe();
}

Status SyslogEventPublisher::populateEventContext(const std::string& line,
                                                  SyslogEventContextRef& ec) {
  boost::tokenizer<RsyslogCsvSeparator> tokenizer(line);
  auto key = kCsvFields.begin();
  for (std::string value : tokenizer) {
    if (key == kCsvFields.end()) {
      return Status(1, "Received more fields than expected");
    }

    boost::trim(value);
    if (*key == "time") {
      ec->fields["datetime"] = value;
    } else if (*key == "tag" && !value.empty() && value.back() == ':') {
      // rsyslog sends "tag" with a trailing colon that we don't need
      ec->fields.emplace(*key, value.substr(0, value.size() - 1));
    } else {
      ec->fields.emplace(*key, value);
    }
    ++key;
  }

  if (key == kCsvFields.end()) {
    return Status(0, "OK");
  } else {
    return Status(1, "Received fewer fields than expected");
  }
}

bool SyslogEventPublisher::shouldFire(const SyslogSubscriptionContextRef& sc,
                                      const SyslogEventContextRef& ec) const {
  return true;
}
}
