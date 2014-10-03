// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/events/darwin/fsevents.h"

#include <glog/logging.h>

namespace osquery {

REGISTER_EVENTTYPE(FSEventsEventPublisher);

std::map<FSEventStreamEventFlags, std::string> kMaskActions = {
    {kFSEventStreamEventFlagItemChangeOwner, "ATTRIBUTES_MODIFIED"},
    {kFSEventStreamEventFlagItemXattrMod, "ATTRIBUTES_MODIFIED"},
    {kFSEventStreamEventFlagItemCreated, "CREATED"},
    {kFSEventStreamEventFlagItemRemoved, "DELETED"},
    {kFSEventStreamEventFlagItemModified, "UPDATED"},
    {kFSEventStreamEventFlagItemRenamed, "MOVED_TO"}, };

void FSEventsEventPublisher::restart() {
  if (paths_.empty()) {
    // There are no paths to watch.
    return;
  }

  if (run_loop_ == nullptr) {
    // There is no run loop to restart.
    return;
  }

  // Build paths as CFStrings
  std::vector<CFStringRef> cf_paths;
  for (const auto& path : paths_) {
    auto cf_path =
        CFStringCreateWithCString(NULL, path.c_str(), kCFStringEncodingUTF8);
    cf_paths.push_back(cf_path);
  }

  // The FSEvents watch takes a CFArrayRef
  auto watch_list = CFArrayCreate(NULL,
                                  reinterpret_cast<const void**>(&cf_paths[0]),
                                  cf_paths.size(),
                                  &kCFTypeArrayCallBacks);
  
  // Remove any existing stream.
  stop();

  // Create the FSEvent stream
  stream_ = FSEventStreamCreate(NULL,
                                &FSEventsEventPublisher::Callback,
                                NULL,
                                watch_list,
                                kFSEventStreamEventIdSinceNow,
                                1,
                                kFSEventStreamCreateFlagFileEvents |
                                    kFSEventStreamCreateFlagNoDefer);
  if (stream_) {
    // Schedule the stream on the run loop.
    FSEventStreamScheduleWithRunLoop(stream_, run_loop_, kCFRunLoopDefaultMode);
    FSEventStreamStart(stream_);
    stream_started_ = true;
  } else {
    LOG(ERROR) << "Cannot create FSEvent stream";
  }

  // Clean up strings, watch list, and context.
  CFRelease(watch_list);
  for (auto& cf_path : cf_paths) {
    CFRelease(cf_path);
  }
}

void FSEventsEventPublisher::stop() {
  // Stop the stream.
  if (stream_ != nullptr) {
    FSEventStreamStop(stream_);
    stream_started_ = false;
    FSEventStreamUnscheduleFromRunLoop(
        stream_, run_loop_, kCFRunLoopDefaultMode);
    FSEventStreamInvalidate(stream_);
    FSEventStreamRelease(stream_);

    stream_ = nullptr;
  }

  // Stop the run loop.
  if (run_loop_ != nullptr) {
    CFRunLoopStop(run_loop_);
  }
}

void FSEventsEventPublisher::tearDown() {
  stop();

  // Do not keep a reference to the run loop.
  run_loop_ = nullptr;
}

void FSEventsEventPublisher::configure() {
  // Rebuild the watch paths.
  paths_.clear();
  for (auto& monitor : monitors_) {
    auto fs_monitor = getMonitorContext(monitor->context);
    paths_.insert(fs_monitor->path);
  }

  // There were no paths in the monitors?
  if (paths_.size() == 0) {
    return;
  }

  restart();
}

Status FSEventsEventPublisher::run() {
  // The run entrypoint executes in a dedicated thread.
  if (run_loop_ == nullptr) {
    run_loop_ = CFRunLoopGetCurrent();
    // Restart the stream creation.
    restart();
  }

  // Start the run loop, it may be removed with a tearDown.
  CFRunLoopRun();
  return Status(0, "OK");
}

void FSEventsEventPublisher::Callback(ConstFSEventStreamRef stream,
                                 void* callback_info,
                                 size_t num_events,
                                 void* event_paths,
                                 const FSEventStreamEventFlags fsevent_flags[],
                                 const FSEventStreamEventId fsevent_ids[]) {
  for (size_t i = 0; i < num_events; ++i) {
    auto ec = createEventContext();
    ec->fsevent_stream = stream;
    ec->fsevent_flags = fsevent_flags[i];
    ec->fsevent_id = fsevent_ids[i];

    // Record the string-version of the first matched mask bit.
    for (const auto& action : kMaskActions) {
      if (ec->fsevent_flags & action.first) {
        ec->action = action.second;
        break;
      }
    }

    ec->path = std::string(((char**)event_paths)[i]);
    EventFactory::fire<FSEventsEventPublisher>(ec);
  }
}

bool FSEventsEventPublisher::shouldFire(const FSEventsMonitorContextRef mc,
                                   const FSEventsEventContextRef ec) {
  ssize_t found = ec->path.find(mc->path);
  if (found != 0) {
    return false;
  }

  if (mc->mask != 0 && !(ec->fsevent_flags & mc->mask)) {
    // Compare the event context mask to the monitor context.
    return false;
  }
  return true;
}

void FSEventsEventPublisher::flush(bool async) {
  if (stream_ != nullptr && stream_started_) {
    if (async) {
      FSEventStreamFlushAsync(stream_);
    } else {
      FSEventStreamFlushSync(stream_);
    }
  }
}

size_t FSEventsEventPublisher::numMonitoredPaths() { return paths_.size(); }

bool FSEventsEventPublisher::isStreamRunning() {
  if (stream_ == nullptr || !stream_started_) {
    return false;
  }

  if (run_loop_ == nullptr) {
    return false;
  }

  return CFRunLoopIsWaiting(run_loop_);
}
}
