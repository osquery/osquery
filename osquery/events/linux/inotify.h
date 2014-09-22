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

const EventTypeID kINotifyEventTypeID = "INotifyEventType";

struct INotifyMonitorContext : public MonitorContext {
  std::string path;
};

struct INotifyEventContext : public EventContext {
  boost::shared_ptr<struct inotify_event> event;
};

typedef boost::shared_ptr<INotifyEventContext> INotifyEventContextRef;
typedef boost::shared_ptr<INotifyMonitorContext> INotifyMonitorContextRef;

// Thread-safe containers
typedef std::vector<int> DescriptorVector;
typedef std::map<std::string, int> PathDescriptorMap;
typedef std::map<int, std::string> DescriptorPathMap;
// typedef std::vector<int> RemovedDescriptorsVector;
// typedef std::vector<int> RemovedWatchesVector;

class INotifyEventType : public EventType {
  DECLARE_EVENTTYPE(kINotifyEventTypeID,
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
