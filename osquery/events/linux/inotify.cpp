/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <fnmatch.h>
#include <linux/limits.h>
#include <poll.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/events/linux/inotify.h"

namespace fs = boost::filesystem;

namespace osquery {

static const int kINotifyMLatency = 200;
static const uint32_t kINotifyBufferSize =
    (10 * ((sizeof(struct inotify_event)) + NAME_MAX + 1));

std::map<int, std::string> kMaskActions = {
    {IN_ACCESS, "ACCESSED"},
    {IN_ATTRIB, "ATTRIBUTES_MODIFIED"},
    {IN_CLOSE_WRITE, "UPDATED"},
    {IN_CREATE, "CREATED"},
    {IN_DELETE, "DELETED"},
    {IN_MODIFY, "UPDATED"},
    {IN_MOVED_FROM, "MOVED_FROM"},
    {IN_MOVED_TO, "MOVED_TO"},
    {IN_OPEN, "OPENED"},
};

const uint32_t kFileDefaultMasks = IN_MOVED_TO | IN_MOVED_FROM | IN_MODIFY |
                                   IN_DELETE | IN_CREATE | IN_CLOSE_WRITE |
                                   IN_ATTRIB;
const uint32_t kFileAccessMasks = IN_OPEN | IN_ACCESS;

REGISTER(INotifyEventPublisher, "event_publisher", "inotify");

Status INotifyEventPublisher::setUp() {
  inotify_handle_ = ::inotify_init();
  // If this does not work throw an exception.
  if (inotify_handle_ == -1) {
    return Status(1, "Could not start inotify: inotify_init failed");
  }

  WriteLock lock(scratch_mutex_);
  scratch_ = (char*)malloc(kINotifyBufferSize);
  if (scratch_ == nullptr) {
    return Status(1, "Could not allocate scratch space");
  }
  return Status(0, "OK");
}

bool INotifyEventPublisher::monitorSubscription(
    INotifySubscriptionContextRef& sc, bool add_watch) {
  sc->discovered_ = sc->path;
  if (sc->path.find("**") != std::string::npos) {
    sc->recursive = true;
    sc->discovered_ = sc->path.substr(0, sc->path.find("**"));
    sc->path = sc->discovered_;
  }

  if (sc->path.find('*') != std::string::npos) {
    // If the wildcard exists within the file (leaf), remove and monitor the
    // directory instead. Apply a fnmatch on fired events to filter leafs.
    auto fullpath = fs::path(sc->path);
    if (fullpath.filename().string().find('*') != std::string::npos) {
      sc->discovered_ = fullpath.parent_path().string() + '/';
    }

    if (sc->discovered_.find('*') != std::string::npos) {
      // If a wildcard exists within the tree (stem), resolve at configure
      // time and monitor each path.
      std::vector<std::string> paths;
      resolveFilePattern(sc->discovered_, paths);
      for (const auto& _path : paths) {
        addMonitor(_path, sc->mask, sc->recursive, add_watch);
      }
      sc->recursive_match = sc->recursive;
      return true;
    }
  }

  if (isDirectory(sc->discovered_) && sc->discovered_.back() != '/') {
    sc->path += '/';
    sc->discovered_ += '/';
  }
  return addMonitor(sc->discovered_, sc->mask, sc->recursive, add_watch);
}

void INotifyEventPublisher::configure() {
  if (inotify_handle_ == -1) {
    // This publisher has not been setup correctly.
    return;
  }

  for (auto& sub : subscriptions_) {
    // Anytime a configure is called, try to monitor all subscriptions.
    // Configure is called as a response to removing/adding subscriptions.
    // This means recalculating all monitored paths.
    auto sc = getSubscriptionContext(sub->context);
    if (sc->discovered_.size() > 0) {
      continue;
    }
    monitorSubscription(sc);
  }
}

void INotifyEventPublisher::tearDown() {
  if (inotify_handle_ > -1) {
    ::close(inotify_handle_);
  }
  inotify_handle_ = -1;

  WriteLock lock(scratch_mutex_);
  if (scratch_ != nullptr) {
    free(scratch_);
    scratch_ = nullptr;
  }
}

Status INotifyEventPublisher::restartMonitoring() {
  if (last_restart_ != 0 && getUnixTime() - last_restart_ < 10) {
    return Status(1, "Overflow");
  }

  last_restart_ = getUnixTime();
  VLOG(1) << "inotify was overflown, attempting to restart handle";

  // Create a copy of the descriptors, then remove each.
  auto descriptors = descriptors_;
  for (const auto& desc : descriptors) {
    removeMonitor(desc, true);
  }

  {
    // Then remove all path/descriptor mappings.
    WriteLock lock(path_mutex_);
    path_descriptors_.clear();
    descriptor_paths_.clear();
  }

  // Reconfigure ourself, the subscribers will not reconfigure.
  configure();
  return Status(0, "OK");
}

Status INotifyEventPublisher::run() {
  struct pollfd fds[1];
  fds[0].fd = getHandle();
  fds[0].events = POLLIN;
  int selector = ::poll(fds, 1, 1000);
  if (selector == -1) {
    LOG(WARNING) << "Could not read inotify handle";
    return Status(1, "INotify handle failed");
  }

  if (selector == 0) {
    // Read timeout.
    return Status(0, "Continue");
  }

  if (!(fds[0].revents & POLLIN)) {
    return Status(0, "Invalid poll response");
  }

  WriteLock lock(scratch_mutex_);
  ssize_t record_num = ::read(getHandle(), scratch_, kINotifyBufferSize);
  if (record_num == 0 || record_num == -1) {
    return Status(1, "INotify read failed");
  }

  for (char* p = scratch_; p < scratch_ + record_num;) {
    // Cast the inotify struct, make shared pointer, and append to contexts.
    auto event = reinterpret_cast<struct inotify_event*>(p);
    if (event->mask & IN_Q_OVERFLOW) {
      // The inotify queue was overflown (remove all paths).
      Status stat = restartMonitoring();
      if (!stat.ok()) {
        return stat;
      }
    }

    if (event->mask & IN_IGNORED) {
      // This inotify watch was removed.
      removeMonitor(event->wd, false);
    } else if (event->mask & IN_MOVE_SELF) {
      // This inotify path was moved, but is still watched.
      removeMonitor(event->wd, true);
    } else if (event->mask & IN_DELETE_SELF) {
      // A file was moved to replace the watched path.
      removeMonitor(event->wd, false);
    } else {
      auto ec = createEventContextFrom(event);
      if (!ec->action.empty()) {
        fire(ec);
      }
    }
    // Continue to iterate
    p += (sizeof(struct inotify_event)) + event->len;
  }

  pauseMilli(kINotifyMLatency);
  return Status(0, "OK");
}

INotifyEventContextRef INotifyEventPublisher::createEventContextFrom(
    struct inotify_event* event) const {
  auto shared_event = std::make_shared<struct inotify_event>(*event);
  auto ec = createEventContext();
  ec->event = shared_event;

  // Get the pathname the watch fired on.
  {
    WriteLock lock(path_mutex_);
    if (descriptor_paths_.find(event->wd) == descriptor_paths_.end()) {
      // return a blank event context if we can't find the paths for the event
      return ec;
    } else {
      ec->path = descriptor_paths_.at(event->wd);
    }
  }

  if (event->len > 1) {
    ec->path += event->name;
  }

  for (const auto& action : kMaskActions) {
    if (event->mask & action.first) {
      ec->action = action.second;
      break;
    }
  }
  return ec;
}

bool INotifyEventPublisher::shouldFire(const INotifySubscriptionContextRef& sc,
                                       const INotifyEventContextRef& ec) const {
  // The subscription may supply a required event mask.
  if (sc->mask != 0 && !(ec->event->mask & sc->mask)) {
    return false;
  }

  if (sc->recursive && !sc->recursive_match) {
    ssize_t found = ec->path.find(sc->path);
    if (found != 0) {
      return false;
    }
  } else if (ec->path == sc->path) {
    return true;
  } else if (fnmatch((sc->path + "*").c_str(),
                     ec->path.c_str(),
                     FNM_PATHNAME | FNM_CASEFOLD |
                         ((sc->recursive_match) ? FNM_LEADING_DIR : 0)) != 0) {
    // Only apply a leading-dir match if this is a recursive watch with a
    // match requirement (an inline wildcard with ending recursive wildcard).
    return false;
  }

  // inotify will not monitor recursively, new directories need watches.
  if (sc->recursive && ec->action == "CREATED" && isDirectory(ec->path)) {
    const_cast<INotifyEventPublisher*>(this)
        ->addMonitor(ec->path + '/', sc->mask, true);
  }

  return true;
}

bool INotifyEventPublisher::addMonitor(const std::string& path,
                                       uint32_t mask,
                                       bool recursive,
                                       bool add_watch) {
  if (!isPathMonitored(path)) {
    int watch = ::inotify_add_watch(
        getHandle(), path.c_str(), ((mask == 0) ? kFileDefaultMasks : mask));
    if (add_watch && watch == -1) {
      LOG(WARNING) << "Could not add inotify watch on: " << path;
      return false;
    }

    {
      WriteLock lock(path_mutex_);
      // Keep a list of the watch descriptors
      descriptors_.push_back(watch);
      // Keep a map of the path -> watch descriptor
      path_descriptors_[path] = watch;
      // Keep a map of the opposite (descriptor -> path)
      descriptor_paths_[watch] = path;
    }
  }

  if (recursive && isDirectory(path).ok()) {
    std::vector<std::string> children;
    // Get a list of children of this directory (requested recursive watches).
    listDirectoriesInDirectory(path, children, true);

    boost::system::error_code ec;
    for (const auto& child : children) {
      auto canonicalized = fs::canonical(child, ec).string() + '/';
      addMonitor(canonicalized, mask, false);
    }
  }

  return true;
}

bool INotifyEventPublisher::removeMonitor(const std::string& path, bool force) {
  {
    WriteLock lock(path_mutex_);
    // If force then remove from INotify, otherwise cleanup file descriptors.
    if (path_descriptors_.find(path) == path_descriptors_.end()) {
      return false;
    }
  }

  int watch = 0;
  {
    WriteLock lock(path_mutex_);
    watch = path_descriptors_[path];
    path_descriptors_.erase(path);
    descriptor_paths_.erase(watch);

    auto position = std::find(descriptors_.begin(), descriptors_.end(), watch);
    descriptors_.erase(position);
  }

  if (force) {
    ::inotify_rm_watch(getHandle(), watch);
  }
  return true;
}

bool INotifyEventPublisher::removeMonitor(int watch, bool force) {
  std::string path;
  {
    WriteLock lock(path_mutex_);
    if (descriptor_paths_.find(watch) == descriptor_paths_.end()) {
      return false;
    }
    path = descriptor_paths_[watch];
  }
  return removeMonitor(path, force);
}

void INotifyEventPublisher::removeSubscriptions(const std::string& subscriber) {
  auto paths = descriptor_paths_;
  for (const auto& path : paths) {
    removeMonitor(path.first, true);
  }
  EventPublisherPlugin::removeSubscriptions(subscriber);
}

bool INotifyEventPublisher::isPathMonitored(const std::string& path) const {
  WriteLock lock(path_mutex_);
  std::string parent_path;
  if (!isDirectory(path).ok()) {
    if (path_descriptors_.find(path) != path_descriptors_.end()) {
      // Path is a file, and is directly monitored.
      return true;
    }
    // Important to add a trailing "/" for inotify.
    parent_path = fs::path(path).parent_path().string() + '/';
  } else {
    parent_path = path;
  }
  // Directory or parent of file monitoring
  auto path_iterator = path_descriptors_.find(parent_path);
  return (path_iterator != path_descriptors_.end());
}
}
