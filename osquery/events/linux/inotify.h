// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <map>
#include <string>
#include <vector>

#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

#include <sys/inotify.h>
#include <sys/stat.h>

#include "osquery/status.h"
#include "osquery/events.h"

namespace osquery {

struct INotifyMonitorContext : public MonitorContext {
  /// Monitor the following filesystem path.
  std::string path;
  /// Limit the actions to the monitored mask.
  uint32_t mask;
  /// Treat this path as a directory and monitor recursively.
  bool recursive;

  INotifyMonitorContext() : mask(0), recursive(false) {}
};

struct INotifyEventContext : public EventContext {
  boost::shared_ptr<struct inotify_event> event;
  std::string path;
  std::string action;
};

typedef boost::shared_ptr<INotifyEventContext> INotifyEventContextRef;
typedef boost::shared_ptr<INotifyMonitorContext> INotifyMonitorContextRef;

// Thread-safe containers
typedef std::vector<int> DescriptorVector;
typedef std::map<std::string, int> PathDescriptorMap;
typedef std::map<int, std::string> DescriptorPathMap;

class INotifyEventType : public EventType {
  DECLARE_EVENTTYPE(INotifyEventType,
                    INotifyMonitorContext,
                    INotifyEventContext);

 public:
  void setUp();
  void configure();
  void tearDown();

  Status run();
  Status addMonitor(const MonitorRef monitor);

  INotifyEventType() : EventType() { inotify_handle_ = -1; }

  bool isHandleOpen() { return inotify_handle_ > 0; }

 private:
  INotifyEventContextRef createEventContext(struct inotify_event* event);

 private:
  bool isMonitored(const std::string& path);
  bool shouldFire(const INotifyMonitorContextRef mc,
                  const INotifyEventContextRef ec);
  int getHandle() { return inotify_handle_; }

  void processDirEvent(struct inotify_event* event);
  void processNodeEvent(struct inotify_event* event);
  void processEvent(struct inotify_event* event);

  // Consider an event queue if separating buffering from firing/servicing.
  DescriptorVector descriptors_;
  PathDescriptorMap path_descriptors_;
  DescriptorPathMap descriptor_paths_;
  int inotify_handle_;
};
}
