/*
 *  Copyright (c) 2014, Facebook, Inc.
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

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/events/linux/inotify.h"

namespace fs = boost::filesystem;

namespace osquery {

int kINotifyMLatency = 200;

static const uint32_t BUFFER_SIZE =
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

REGISTER(INotifyEventPublisher, "event_publisher", "inotify");

Status INotifyEventPublisher::setUp() {
  inotify_handle_ = ::inotify_init();
  // If this does not work throw an exception.
  if (inotify_handle_ == -1) {
    return Status(1, "Could not start inotify: inotify_init failed");
  }
  return Status(0, "OK");
}

void INotifyEventPublisher::configure() {
  for (auto& sub : subscriptions_) {
    // Anytime a configure is called, try to monitor all subscriptions.
    // Configure is called as a response to removing/adding subscriptions.
    // This means recalculating all monitored paths.
    auto sc = getSubscriptionContext(sub->context);
    if (sc->discovered_.size() > 0) {
      continue;
    }

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
        sc->discovered_ = fullpath.parent_path().string();
      }

      if (sc->discovered_.find('*') != std::string::npos) {
        // If a wildcard exists within the tree (stem), resolve at configure
        // time and monitor each path.
        std::vector<std::string> paths;
        resolveFilePattern(sc->discovered_, paths);
        for (const auto& _path : paths) {
          addMonitor(_path, sc->recursive);
        }
        sc->recursive_match = sc->recursive;
        continue;
      }
    }
    addMonitor(sc->discovered_, sc->recursive);
  }
}

void INotifyEventPublisher::tearDown() {
  ::close(inotify_handle_);
  inotify_handle_ = -1;
}

Status INotifyEventPublisher::restartMonitoring(){
  if (last_restart_ != 0 && getUnixTime() - last_restart_ < 10) {
    return Status(1, "Overflow");
  }
  last_restart_ = getUnixTime();
  VLOG(1) << "inotify was overflown, attempting to restart handle";
  for(const auto& desc : descriptors_){
    removeMonitor(desc, 1);
  }
  path_descriptors_.clear();
  descriptor_paths_.clear();
  configure();
  return Status(0, "OK");
}

Status INotifyEventPublisher::run() {
  // Get a while wrapper for free.
  char buffer[BUFFER_SIZE];
  fd_set set;

  FD_ZERO(&set);
  FD_SET(getHandle(), &set);

  struct timeval timeout = {3, 3000};
  int selector = ::select(getHandle() + 1, &set, nullptr, nullptr, &timeout);
  if (selector == -1) {
    LOG(ERROR) << "Could not read inotify handle";
    return Status(1, "INotify handle failed");
  }

  if (selector == 0) {
    // Read timeout.
    return Status(0, "Continue");
  }
  ssize_t record_num = ::read(getHandle(), buffer, BUFFER_SIZE);
  if (record_num == 0 || record_num == -1) {
    return Status(1, "INotify read failed");
  }

  for (char* p = buffer; p < buffer + record_num;) {
    // Cast the inotify struct, make shared pointer, and append to contexts.
    auto event = reinterpret_cast<struct inotify_event*>(p);
    if (event->mask & IN_Q_OVERFLOW) {
      // The inotify queue was overflown (remove all paths).
      Status stat = restartMonitoring();
      if(!stat.ok()){
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
      fire(ec);
    }
    // Continue to iterate
    p += (sizeof(struct inotify_event)) + event->len;
  }

  osquery::publisherSleep(kINotifyMLatency);
  return Status(0, "Continue");
}

INotifyEventContextRef INotifyEventPublisher::createEventContextFrom(
    struct inotify_event* event) {
  auto shared_event = std::make_shared<struct inotify_event>(*event);
  auto ec = createEventContext();
  ec->event = shared_event;

  // Get the pathname the watch fired on.
  ec->path = descriptor_paths_[event->wd];
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
  // The subscription may supply a required event mask.
  if (sc->mask != 0 && !(ec->event->mask & sc->mask)) {
    return false;
  }

  // inotify will not monitor recursively, new directories need watches.
  if(sc->recursive && ec->action == "CREATED" && isDirectory(ec->path)){
    const_cast<INotifyEventPublisher*>(this)->addMonitor(ec->path + '/', true);
  }

  return true;
}

bool INotifyEventPublisher::addMonitor(const std::string& path,
                                       bool recursive) {
  if (!isPathMonitored(path)) {
    int watch = ::inotify_add_watch(getHandle(), path.c_str(), IN_ALL_EVENTS);
    if (watch == -1) {
      LOG(ERROR) << "Could not add inotify watch on: " << path;
      return false;
    }

    // Keep a list of the watch descriptors
    descriptors_.push_back(watch);
    // Keep a map of the path -> watch descriptor
    path_descriptors_[path] = watch;
    // Keep a map of the opposite (descriptor -> path)
    descriptor_paths_[watch] = path;
  }

  if (recursive && isDirectory(path).ok()) {
    std::vector<std::string> children;
    // Get a list of children of this directory (requested recursive watches).
    listDirectoriesInDirectory(path, children);

    for (const auto& child : children) {
      addMonitor(child, recursive);
    }
  }

  return true;
}

bool INotifyEventPublisher::removeMonitor(const std::string& path, bool force) {
  // If force then remove from INotify, otherwise cleanup file descriptors.
  if (path_descriptors_.find(path) == path_descriptors_.end()) {
    return false;
  }

  int watch = path_descriptors_[path];
  path_descriptors_.erase(path);
  descriptor_paths_.erase(watch);

  auto position = std::find(descriptors_.begin(), descriptors_.end(), watch);
  descriptors_.erase(position);

  if (force) {
    ::inotify_rm_watch(getHandle(), watch);
  }
  return true;
}

bool INotifyEventPublisher::removeMonitor(int watch, bool force) {
  if (descriptor_paths_.find(watch) == descriptor_paths_.end()) {
    return false;
  }

  auto path = descriptor_paths_[watch];
  return removeMonitor(path, force);
}

bool INotifyEventPublisher::isPathMonitored(const std::string& path) {
  boost::filesystem::path parent_path;
  if (!isDirectory(path).ok()) {
    if (path_descriptors_.find(path) != path_descriptors_.end()) {
      // Path is a file, and is directly monitored.
      return true;
    }
    if (!getDirectory(path, parent_path).ok()) {
      // Could not get parent of unmonitored file.
      return false;
    }
  } else {
    parent_path = path;
  }

  // Directory or parent of file monitoring
  auto path_iterator = path_descriptors_.find(parent_path.string());
  return (path_iterator != path_descriptors_.end());
}
}
