/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fnmatch.h>

#include <boost/filesystem.hpp>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/events/eventfactory.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

#include "osquery/events/darwin/fsevents.h"

/**
 * @brief FSEvents needs a real/absolute path for watches.
 *
 * When adding a subscription, FSEvents will resolve a depth of recursive
 * symlinks. Increasing the max will make tolerance to odd setups more robust
 * but introduce additional latency during startup.
 */
#define FSEVENTS_MAX_SYMLINK_DEPTH 5

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_bool(enable_file_events);

std::map<FSEventStreamEventFlags, std::string> kMaskActions = {
    {kFSEventStreamEventFlagItemChangeOwner, "ATTRIBUTES_MODIFIED"},
    {kFSEventStreamEventFlagItemXattrMod, "ATTRIBUTES_MODIFIED"},
    {kFSEventStreamEventFlagItemInodeMetaMod, "ATTRIBUTES_MODIFIED"},
    {kFSEventStreamEventFlagItemCreated, "CREATED"},
    {kFSEventStreamEventFlagItemRemoved, "DELETED"},
    {kFSEventStreamEventFlagItemModified, "UPDATED"},
    {kFSEventStreamEventFlagItemRenamed, "MOVED_TO"},
    {kFSEventStreamEventFlagMustScanSubDirs, "COLLISION_WITHIN"},
    {kFSEventStreamEventFlagMount, "MOUNTED"},
    {kFSEventStreamEventFlagUnmount, "UNMOUNTED"},
    {kFSEventStreamEventFlagRootChanged, "ROOT_CHANGED"},
};

REGISTER(FSEventsEventPublisher, "event_publisher", "fsevents");

void FSEventsSubscriptionContext::requireAction(const std::string& action) {
  for (const auto& bit : kMaskActions) {
    if (action == bit.second) {
      mask = mask & bit.first;
    }
  }
}

void FSEventsEventPublisher::restart() {
  // Remove any existing stream.
  stop();

  // Build paths as CFStrings
  WriteLock lock(mutex_);
  if (run_loop_ == nullptr) {
    return;
  }

  if (paths_.empty()) {
    // There are no paths to watch.
    return;
  }

  std::vector<CFStringRef> cf_paths;
  for (const auto& path : paths_) {
    auto cf_path =
        CFStringCreateWithCString(nullptr, path.c_str(), kCFStringEncodingUTF8);
    cf_paths.push_back(cf_path);
  }

  // The FSEvents watch takes a CFArrayRef
  auto watch_list = CFArrayCreate(nullptr,
                                  reinterpret_cast<const void**>(&cf_paths[0]),
                                  cf_paths.size(),
                                  &kCFTypeArrayCallBacks);

  // Set stream flags.
  auto flags =
      kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot;
  if (no_defer_) {
    flags |= kFSEventStreamCreateFlagNoDefer;
  }
  if (no_self_) {
    flags |= kFSEventStreamCreateFlagIgnoreSelf;
  }

  // Create the FSEvent stream.
  stream_ = FSEventStreamCreate(nullptr,
                                &FSEventsEventPublisher::Callback,
                                nullptr,
                                watch_list,
                                kFSEventStreamEventIdSinceNow,
                                1,
                                flags);
  if (stream_ != nullptr) {
    // Schedule the stream on the run loop.
    FSEventStreamScheduleWithRunLoop(stream_, run_loop_, kCFRunLoopDefaultMode);
    if (FSEventStreamStart(stream_)) {
      stream_started_ = true;
    } else {
      LOG(ERROR) << "Cannot start FSEvent stream: FSEventStreamStart failed";
    }
  } else {
    LOG(ERROR) << "Cannot create FSEvent stream: FSEventStreamCreate failed";
  }

  // Clean up strings, watch list, and context.
  CFRelease(watch_list);
  for (auto& cf_path : cf_paths) {
    CFRelease(cf_path);
  }
}

void FSEventsEventPublisher::stop() {
  // Stop the stream.
  WriteLock lock(mutex_);
  if (run_loop_ == nullptr) {
    // No need to stop if there is not run loop.
    return;
  }

  if (stream_ != nullptr) {
    FSEventStreamFlushSync(stream_);
    FSEventStreamStop(stream_);
    stream_started_ = false;
    FSEventStreamUnscheduleFromRunLoop(
        stream_, run_loop_, kCFRunLoopDefaultMode);
    FSEventStreamInvalidate(stream_);
    FSEventStreamRelease(stream_);
    stream_ = nullptr;
  }

  // Stop the run loop.
  CFRunLoopStop(run_loop_);
}

void FSEventsEventPublisher::tearDown() {
  if (!FLAGS_enable_file_events) {
    return;
  }

  stop();

  // Do not keep a reference to the run loop.
  WriteLock lock(mutex_);
  run_loop_ = nullptr;
}

std::set<std::string> FSEventsEventPublisher::transformSubscription(
    FSEventsSubscriptionContextRef& sc) const {
  std::set<std::string> paths;
  sc->discovered_ = sc->path;
  if (sc->path.find("**") != std::string::npos) {
    // Double star will indicate recursive matches, restricted to endings.
    sc->recursive = true;
    sc->discovered_ = sc->path.substr(0, sc->path.find("**"));
    // Remove '**' from the subscription path (used to match later).
    sc->path = sc->discovered_;
  }

  // If the path 'still' OR 'either' contains a single wildcard.
  if (sc->path.find('*') != std::string::npos) {
    // First check if the wildcard is applied to the end.
    auto fullpath = fs::path(sc->path);
    if (fullpath.filename().string().find('*') != std::string::npos) {
      sc->discovered_ = fullpath.parent_path().string();
    }

    // FSEvents needs a real path, if the wildcard is within the path then
    // a configure-time resolve is required.
    if (sc->discovered_.find('*') != std::string::npos) {
      std::vector<std::string> exploded_paths;
      resolveFilePattern(sc->discovered_, exploded_paths);
      for (const auto& path : exploded_paths) {
        paths.insert(path);
      }
      sc->recursive_match = sc->recursive;
      return paths;
    }
  }
  paths.insert(sc->discovered_);
  return paths;
}

void FSEventsEventPublisher::buildExcludePathsSet() {
  auto parser = Config::getParser("file_paths");

  WriteLock lock(subscription_lock_);
  exclude_paths_.clear();

  const auto& doc = parser->getData();
  if (!doc.doc().HasMember("exclude_paths")) {
    return;
  }

  for (const auto& category : doc.doc()["exclude_paths"].GetObject()) {
    for (const auto& excl_path : category.value.GetArray()) {
      std::string pattern = excl_path.GetString();
      if (pattern.empty()) {
        continue;
      }
      exclude_paths_.insert(pattern);
    }
  }
}

void FSEventsEventPublisher::configure() {
  if (!FLAGS_enable_file_events) {
    return;
  }

  // Rebuild the watch paths.
  stop();

  buildExcludePathsSet();

  {
    WriteLock lock(mutex_);
    paths_.clear();
    for (auto& sub : subscriptions_) {
      auto sc = getSubscriptionContext(sub->context);
      if (sc->discovered_.size() > 0) {
        continue;
      }
      auto paths = transformSubscription(sc);
      paths_.insert(paths.begin(), paths.end());
    }
  }

  restart();
}

Status FSEventsEventPublisher::run() {
  if (!FLAGS_enable_file_events) {
    return Status(1, "Publisher disabled via configuration");
  }

  // The run entrypoint executes in a dedicated thread.
  bool needs_reset = false;
  {
    WriteLock lock(mutex_);
    if (run_loop_ == nullptr) {
      needs_reset = true;
      run_loop_ = CFRunLoopGetCurrent();
    }
  }

  // Restart the stream creation.
  if (needs_reset) {
    restart();
  }

  // Start the run loop, it may be removed with a tearDown.
  CFRunLoopRun();
  return Status::success();
}

void FSEventsEventPublisher::Callback(
    ConstFSEventStreamRef stream,
    void* callback_info,
    size_t num_events,
    void* event_paths,
    const FSEventStreamEventFlags fsevent_flags[],
    const FSEventStreamEventId fsevent_ids[]) {
  for (size_t i = 0; i < num_events; ++i) {
    auto ec = createEventContext();
    ec->fsevent_stream = stream;
    ec->fsevent_flags = fsevent_flags[i];
    ec->transaction_id = fsevent_ids[i];
    ec->path = std::string(((char**)event_paths)[i]);

    if (ec->fsevent_flags & kFSEventStreamEventFlagMustScanSubDirs) {
      // The FSEvents thread coalesced events within and will report a root.
      TLOG << "FSEvents collision, root: " << ec->path;
    }

    if (ec->fsevent_flags & kFSEventStreamEventFlagRootChanged) {
      // Must rescan for the changed root.
    }

    if (ec->fsevent_flags & kFSEventStreamEventFlagUnmount) {
      // Should remove the watch on this path.
    }

    if (ec->fsevent_flags & kFSEventStreamEventFlagMount) {
      auto mc = std::make_shared<FSEventsSubscriptionContext>();
      mc->path = ec->path + "/*";
      auto subscription = Subscription::create("file_events", mc);
      auto status = EventFactory::addSubscription("fsevents", subscription);
      auto pub = EventFactory::getEventPublisher("fsevents");
      pub->configure();
    }

    // Record the string-version of the first matched mask bit.
    bool has_action = false;
    for (const auto& action : kMaskActions) {
      if (ec->fsevent_flags & action.first) {
        // Actions may be multiplexed. Fire and event for each.
        ec->action = action.second;
        EventFactory::fire<FSEventsEventPublisher>(ec);
        has_action = true;
      }
    }

    if (!has_action) {
      // If no action was matched for this path event, fire and unknown.
      ec->action = "UNKNOWN";
      EventFactory::fire<FSEventsEventPublisher>(ec);
    }
  }
}

bool FSEventsEventPublisher::shouldFire(
    const FSEventsSubscriptionContextRef& sc,
    const FSEventsEventContextRef& ec) const {
  if (sc->recursive && !sc->recursive_match) {
    ssize_t found = ec->path.find(sc->path);
    if (found != 0) {
      return false;
    }
  } else if (fnmatch((sc->path + "*").c_str(),
                     ec->path.c_str(),
                     FNM_PATHNAME | FNM_CASEFOLD |
                         ((sc->recursive_match) ? FNM_LEADING_DIR : 0)) != 0) {
    // Only apply a leading-dir match if this is a recursive watch with a
    // match requirement (an inline wildcard with ending recursive wildcard).
    return false;
  }

  if (sc->mask != 0 && !(ec->fsevent_flags & sc->mask)) {
    // Compare the event context mask to the subscription context.
    return false;
  }

  auto path = ec->path.substr(0, ec->path.rfind('/'));
  // Need to have two finds,
  // what if somebody excluded an individual file inside a directory
  if (!exclude_paths_.empty() &&
      (exclude_paths_.find(path) || exclude_paths_.find(ec->path))) {
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

size_t FSEventsEventPublisher::numSubscriptionedPaths() const {
  return paths_.size();
}

bool FSEventsEventPublisher::isStreamRunning() const {
  WriteLock lock(mutex_);
  if (stream_ == nullptr || !stream_started_ || run_loop_ == nullptr) {
    return false;
  }

  return CFRunLoopIsWaiting(run_loop_);
}
}
