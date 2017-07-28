#pragma once

#include <map>
#include <set>
#include <vector>

#include <boost/algorithm/hex.hpp>

#include <osquery/events.h>

#include "osquery/core/conversions.h"

namespace osquery {

class BSMRecord {
public:
	std::string path;
	std::vector<std::string> args;
	unsigned long status;
	unsigned int event_id;
	unsigned int euid;
	unsigned int egid;
	unsigned int ruid;
	unsigned int rgid;
	time_t time;
	pid_t pid;
	dev_t dev;
	ino_t inode;

	std::map<std::string, std::string> toMap() {
		return {
			{"time", std::to_string(time)},
			{"pid", std::to_string(pid)},
			{"euid", std::to_string(euid)},
			{"egid", std::to_string(egid)},
			{"status", std::to_string(status)},
			{"path", path},
			{"args", osquery::join(args, " ")},
			{"device", std::to_string(dev)},
			{"ruid", std::to_string(ruid)},
			{"ruid", std::to_string(rgid)}
		};
	}
};

struct OpenBSMSubscriptionContext : public SubscriptionContext {

	// The id of the event you want to alert on (23 for execve for example)
	int event_id;
};

struct OpenBSMEventContext : public EventContext {
	// The event_id of the OpenBSM log
	int event_id;
	// The rest of the data from the log
	std::map<std::string, std::string> event_details;
};

using OpenBSMEventContextRef = std::shared_ptr<OpenBSMEventContext>;
using OpenBSMSubscriptionContextRef = std::shared_ptr<OpenBSMSubscriptionContext>;

/// This is a dispatched service that handles published audit replies.
class OpenBSMConsumerRunner;

class OpenBSMEventPublisher
    : public EventPublisher<OpenBSMSubscriptionContext, OpenBSMEventContext> {
  DECLARE_PUBLISHER("openbsm_events");

 public:
  Status setUp() override;

  void configure() override;

  void tearDown() override;

  Status run() override;

  OpenBSMEventPublisher() : EventPublisher() {}

  virtual ~OpenBSMEventPublisher() {
    tearDown();
  }

 private:
  FILE * audit_pipe;
  /// Apply normal subscription to event matching logic.
  bool shouldFire(const OpenBSMSubscriptionContextRef& mc,
                  const OpenBSMEventContextRef& ec) const override;
};
}