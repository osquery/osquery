#pragma once

#include <set>
#include <string>

#include <Windows.h>
#include <winioctl.h>

#include <osquery/events.h>

#include "osquery/events/pathset.h"

namespace osquery {

extern const DWORD kFileDefaultMask;

class FileEventPublisher;

struct WindowsFileEventSubscriptionContext : public SubscriptionContext {
  std::string category;
  std::string path;
  std::string opath;
  bool recursive;
  DWORDLONG mask;

 private:
  bool mark_for_deletion{false};
  friend class FileEventPublisher;
};

using WindowsFileEventSubscriptionContextRef =
    std::shared_ptr<WindowsFileEventSubscriptionContext>;

struct WindowsFileEventContext : public EventContext {
  std::string path;
  DWORD action;
  USN_RECORD record;
  WindowsFileEventSubscriptionContextRef sub_ctx;
};

using WindowsFileEventContextRef = std::shared_ptr<WindowsFileEventContext>;

using ExcludePathSet = PathSet<patternedPath>;

class FileEventPublisher
    : public EventPublisher<WindowsFileEventSubscriptionContext,
                            WindowsFileEventContext> {
  DECLARE_PUBLISHER("windows_file_events");

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;
  Status run() override;

  Status addSubscription(const SubscriptionRef& SCRef) override;
  void removeSubscriptions(const std::string&) override;

  FileEventPublisher();

  virtual ~FileEventPublisher() {
    tearDown();
  }

 private:
  struct FileTrackingContext {
    std::string path;
    DWORDLONG parent_file_reference;
    std::set<WindowsFileEventSubscriptionContextRef> subscriptions;
  };

  struct DirectoryMonitoringContext {
    std::string path;
    std::set<std::pair<WindowsFileEventSubscriptionContextRef, std::string>>
        subscriptions;
  };

  void insert_tracked_parent_dir(DWORDLONG,
                                 const std::string& path,
                                 const WindowsFileEventSubscriptionContextRef&,
                                 const std::string&);
  void insert_tracked_file(DWORDLONG,
                           const std::string& path,
                           DWORDLONG parentRefNumber,
                           const WindowsFileEventSubscriptionContextRef& sc);

  bool addMonitor(const std::string& path,
                  WindowsFileEventSubscriptionContextRef& sc,
                  bool descend = false);
  void addVolume(char volume);
  bool monitorSubscription(WindowsFileEventSubscriptionContextRef& sc);
  bool addParentMonitor(const std::string& path,
                        const std::string& filter,
                        WindowsFileEventSubscriptionContextRef& sc);

  bool shouldFire(const WindowsFileEventSubscriptionContextRef& sc,
                  const WindowsFileEventContextRef& ec) const;
  void buildExcludePathsSet();

  void process_usn_record(USN_RECORD*);
  std::map<DWORDLONG, FileTrackingContext> tracked_files;
  std::map<DWORDLONG, DirectoryMonitoringContext> tracked_parent_dirs;

  struct PrivateData;
  std::shared_ptr<PrivateData> data;

  ExcludePathSet exclude_paths_;

  char* _scratch{nullptr};
  Mutex _private_data_mutex;
  Mutex _tracking_data_mutex;
  Mutex _scratch_mutex;
};
}
