// Copyright 2004-present Facebook. All Rights Reserved.

#include <sstream>

#include <linux/limits.h>

#include "osquery/events.h"
#include "osquery/filesystem.h"
#include "osquery/events/linux/inotify.h"

#include <glog/logging.h>

namespace osquery {

REGISTER_EVENTPUBLISHER(INotifyEventPublisher);

int kINotifyULatency = 200;
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

void INotifyEventPublisher::setUp() {
  inotify_handle_ = ::inotify_init();
  // If this does not work throw an exception.
  if (inotify_handle_ == -1) {
    // Todo: throw exception and DO NOT register this eventtype.
  }
}

void INotifyEventPublisher::configure() {
  for (const auto& sub : subscriptions_) {
    // Anytime a configure is called, try to monitor all subscriptions.
    // Configure is called as a response to removing/adding subscriptions.
    // This means recalculating all monitored paths.
    auto sc = getSubscriptionContext(sub->context);
    addMonitor(sc->path, sc->recursive);
  }
}

void INotifyEventPublisher::tearDown() {
  ::close(inotify_handle_);
  inotify_handle_ = -1;
}

Status INotifyEventPublisher::run() {
  // Get a while wraper for free.
  char buffer[BUFFER_SIZE];
  fd_set set;

  FD_ZERO(&set);
  FD_SET(getHandle(), &set);

  struct timeval timeout = {0, kINotifyULatency};
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
      return Status(1, "Overflow");
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
      auto ec = createEventContext(event);
      fire(ec);
    }
    // Continue to iterate
    p += (sizeof(struct inotify_event)) + event->len;
  }

  ::usleep(kINotifyULatency);
  return Status(0, "Continue");
}

INotifyEventContextRef INotifyEventPublisher::createEventContext(
    struct inotify_event* event) {
  auto shared_event = std::make_shared<struct inotify_event>(*event);
  auto ec = createEventContext();
  ec->event = shared_event;

  // Get the pathname the watch fired on.
  std::ostringstream path;
  path << descriptor_paths_[event->wd];
  if (event->len > 1) {
    path << "/" << event->name;
  }
  ec->path = path.str();

  // Set the action (may be multiple)
  for (const auto& action : kMaskActions) {
    if (event->mask & action.first) {
      ec->action = action.second;
      break;
    }
  }
  return ec;
}

bool INotifyEventPublisher::shouldFire(const INotifySubscriptionContextRef sc,
                                       const INotifyEventContextRef ec) {
  if (!sc->recursive && sc->path != ec->path) {
    // Monitored path is not recursive and path is not an exact match.
    return false;
  }

  if (ec->path.find(sc->path) != 0) {
    // The path does not exist as the base event path.
    return false;
  }

  // The subscription may supply a required event mask.
  if (sc->mask != 0 && !(ec->event->mask & sc->mask)) {
    return false;
  }
  return true;
}

bool INotifyEventPublisher::addMonitor(const std::string& path,
                                       bool recursive) {
  if (!isPathMonitored(path)) {
    int watch = ::inotify_add_watch(getHandle(), path.c_str(), IN_ALL_EVENTS);
    if (watch == -1) {
      LOG(ERROR) << "Could not add inotfy watch on: " << path;
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
    // Get a list of children of this directory (requesed recursive watches).
    if (!listFilesInDirectory(path, children).ok()) {
      return false;
    }

    for (const auto& child : children) {
      // Only watch child directories, a watch on the directory implies files.
      if (isDirectory(child).ok()) {
        addMonitor(child, recursive);
      }
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

  std::string path = descriptor_paths_[watch];
  return removeMonitor(path, force);
}

bool INotifyEventPublisher::isPathMonitored(const std::string& path) {
  std::string parent_path;
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
  return (path_descriptors_.find(parent_path) != path_descriptors_.end());
}
}
