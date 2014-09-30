// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <map>
#include <string>
#include <vector>

#include <boost/make_shared.hpp>

#include <sys/inotify.h>
#include <sys/stat.h>

#include "osquery/status.h"
#include "osquery/events.h"

namespace osquery {

extern std::map<int, std::string> kMaskActions;

/**
 * @brief Monitoring details for INotifyEventType events.
 *
 * This context is specific to INotifyEventType. It allows the monitoring
 * EventModule to set a path (file or directory) and a limited action mask.
 * Events are passed to the monitoring EventModule if they match the context
 * path (or anything within a directory if the path is a directory) and if the
 * event action is part of the mask. If the mask is 0 then all actions are 
 * passed to the EventModule.
 */
struct INotifyMonitorContext : public MonitorContext {
  /// Monitor the following filesystem path.
  std::string path;
  /// Limit the `inotify` actions to the monitored mask (if not 0).
  uint32_t mask;
  /// Treat this path as a directory and monitor recursively.
  bool recursive;

  INotifyMonitorContext() : mask(0), recursive(false) {}

  /**
   * @brief Helper method to map a string action to `inotify` action mask bit.
   *
   * This helper method will set the `mask` value for this MonitorContext. 
   *
   * @param action The string action, a value in kMaskAction%s.
   */
  void requireAction(std::string action) {
    for (const auto& bit : kMaskActions) {
      if (action == bit.second) {
        mask = mask | bit.first;
      }
    }
  }
};

/**
 * @brief Event details for INotifyEventType events.
 */
struct INotifyEventContext : public EventContext {
  /// The inotify_event structure if the EventModule want to interact.
  std::shared_ptr<struct inotify_event> event;
  /// A string path parsed from the inotify_event.
  std::string path;
  /// A string action representing the event action `inotify` bit.
  std::string action;
};

typedef std::shared_ptr<INotifyEventContext> INotifyEventContextRef;
typedef std::shared_ptr<INotifyMonitorContext> INotifyMonitorContextRef;

// Thread-safe containers
typedef std::vector<int> DescriptorVector;
typedef std::map<std::string, int> PathDescriptorMap;
typedef std::map<int, std::string> DescriptorPathMap;

/**
 * @brief A Linux `inotify` EventType.
 *
 * This EventType allows EventModule%s to monitor for Linux `inotify` events.
 * Since these events are limited this EventType will optimize the watch
 * descriptors, keep track of the usage, implement optimizations/priority
 * where possible, and abstract file system events to a path/action context.
 *
 * Uses INotifyMonitorContext and INotifyEventContext for monitoring, eventing.
 */
class INotifyEventType : public EventType {
  DECLARE_EVENTTYPE(INotifyEventType,
                    INotifyMonitorContext,
                    INotifyEventContext);

 public:
  /// Create an `inotify` handle descriptor.
  void setUp();
  void configure();
  /// Release the `inotify` handle descriptor.
  void tearDown();

  Status run();
  /// Overload EventType::addMonitor to perform optimizations at add time.
  Status addMonitor(const MonitorRef monitor);

  INotifyEventType() : EventType() { inotify_handle_ = -1; }
  /// Check if the application-global `inotify` handle is alive.
  bool isHandleOpen() { return inotify_handle_ > 0; }

 private:
  INotifyEventContextRef createEventContext(struct inotify_event* event);
  /// Check all added Monitor%s for a path.
  bool isMonitored(const std::string& path);
  /// Given a MonitorContext and INotifyEventContext match path and action.
  bool shouldFire(const INotifyMonitorContextRef mc,
                  const INotifyEventContextRef ec);
  /// Get the INotify file descriptor.
  int getHandle() { return inotify_handle_; }

  // Consider an event queue if separating buffering from firing/servicing.
  DescriptorVector descriptors_;
  PathDescriptorMap path_descriptors_;
  DescriptorPathMap descriptor_paths_;
  int inotify_handle_;
};
}
