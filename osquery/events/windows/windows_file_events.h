#pragma once

#include <Windows.h>
#include <winioctl.h>

#include <string>

#include <osquery/events.h>

namespace osquery {

  struct WindowsFileEventSubscriptionContext : public SubscriptionContext {
    std::string category;
    std::string path;
    std::string opath;
    bool recursive;
    DWORDLONG mask;
  };

  using WindowsFileEventSubscriptionContextRef = std::shared_ptr<WindowsFileEventSubscriptionContext>;

  struct WindowsFileEventContext : public EventContext { 
    std::string path;
    DWORD action;
    USN_RECORD record;
  };

  class FileEventPublisher : public EventPublisher<WindowsFileEventSubscriptionContext, WindowsFileEventContext> {
    DECLARE_PUBLISHER("windows_file_events");

    public:
    Status setUp() override;
    void configure() override;
    void tearDown() override;
    Status run() override;

    Status addSubscription(const SubscriptionRef &SCRef) override;

    FileEventPublisher();

    virtual ~FileEventPublisher() {
      tearDown();
    }

    private:
    void process_usn_record(USN_RECORD *);
    std::map<DWORDLONG, std::string> tracked_files;
    std::map<DWORDLONG, std::string> tracked_parent_dirs;

    struct PrivateData;
    std::shared_ptr<PrivateData> data;

    char *_scratch{nullptr};
    Mutex _private_data_mutex;
    Mutex _tracked_data_mutex;
    Mutex _scratch_mutex;
  };
}
