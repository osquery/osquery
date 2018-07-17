#include <string>
#include <sstream>

#include <shlwapi.h>

#include <boost/filesystem.hpp>

#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/filesystem.h>

#include "osquery/events/windows/windows_file_events.h"

namespace fs = boost::filesystem;

constexpr unsigned int BUF_LEN = 4096;

namespace osquery {

  REGISTER(FileEventPublisher, "event_publisher", "windows_file_events");

  bool operator==(const WindowsFileEventSubscriptionContext &lhs, const WindowsFileEventSubscriptionContext &rhs) {
    return ((lhs.category == rhs.category) && (lhs.opath == rhs.opath));
  }

  struct FileEventPublisher::PrivateData final {
    std::map<char, USN> volumes;
  };

  bool get_file_ref_number(const std::string &path, DWORDLONG &fileRefNumber)
  {
    DWORD flags = 0;
    if (isDirectory(path).ok())
      flags = FILE_FLAG_BACKUP_SEMANTICS;

    HANDLE h = ::CreateFile(path.c_str(),
        GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        flags,
        NULL);
    if (INVALID_HANDLE_VALUE == h) 
    {
      LOG(WARNING) << "unable to get handle to path " << path << ": " << ::GetLastError();
      return false;
    }

    BY_HANDLE_FILE_INFORMATION info;
    if (!::GetFileInformationByHandle(h, &info)) {
      LOG(WARNING) << "unable to get file information for " << path << ": " << ::GetLastError();
      ::CloseHandle(h);
      return false;
    }

    fileRefNumber = ((DWORDLONG)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    ::CloseHandle(h);
    return true;
  }

  FileEventPublisher::FileEventPublisher() : data(new PrivateData) {
  }


  bool FileEventPublisher::shouldFire(const WindowsFileEventSubscriptionContextRef& sc,
                                       const WindowsFileEventContextRef& ec) const {
    if (sc.get() != ec->sub_ctx.get()) {
      return false;
    }

    return true;
  }

  Status FileEventPublisher::addSubscription(const SubscriptionRef& subscription) {
    WriteLock lock(subscription_lock_);
    auto received_sc = getSubscriptionContext(subscription->context);
    for (auto& sub : subscriptions_) {
      auto sc = getSubscriptionContext(sub->context);
      if (*received_sc == *sc) {
        if (sc->mark_for_deletion) {
          sc->mark_for_deletion = false;
          return Status(0);
        }
        // Returning non zero signals EventSubscriber::subscribe
        // do not bump up subscription_count_.
        return Status(1);
      }
    }

    subscriptions_.push_back(subscription);
    return Status(0);
  }

  void FileEventPublisher::addVolume(char volume) {
    WriteLock(_private_data_mutex);
    auto search = data->volumes.find(volume);
    if (search == data->volumes.end()) {
      char *volumePath = "\\\\.\\c:";
      volumePath[5] = volume;

      //collect the most recent USN and add the key,val pair here
      auto hVol = ::CreateFile( volumePath,
          GENERIC_READ | GENERIC_WRITE, 
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          NULL,
          OPEN_EXISTING,
          0,
          NULL);

      if( hVol == INVALID_HANDLE_VALUE ) {
        LOG(WARNING) << "CreateFile failed: " << GetLastError();
        return;
      }

      USN_JOURNAL_DATA JournalData;
      DWORD dwBytes = 0;
      if( !::DeviceIoControl( hVol, 
            FSCTL_QUERY_USN_JOURNAL, 
            NULL,
            0,
            &JournalData,
            sizeof(JournalData),
            &dwBytes,
            NULL) )
      {
        LOG(WARNING) << "Query journal failed: " <<  GetLastError();
        return;
      }

      data->volumes[volume] = JournalData.NextUsn;
    }
  }

  bool FileEventPublisher::addMonitor(const std::string &path, WindowsFileEventSubscriptionContextRef& sc)
  {
    LOG(WARNING) << "addMonitor(" << path << ")";
    if (FALSE == ::PathFileExistsA(path.c_str())) {
      LOG(WARNING) << "Path not found: " << path.c_str() << " " << ::GetLastError();
      return false;
    }

    DWORDLONG fileRefNumber = 0;
    if (!get_file_ref_number(path, fileRefNumber))
    {
      LOG(WARNING) << "Could not get file reference number: " << path.c_str() << " " << ::GetLastError();
      return false;
    }

    addVolume(path[0]);

    auto tf_iter = tracked_files.find(fileRefNumber);
    if (tf_iter == tracked_files.end()) {
      tracked_files[fileRefNumber] = {path, {sc} };
    } else {
      tf_iter->second.subscriptions.insert(sc);
    }

    LOG(WARNING) << "added " << path << " to tracked files";

    if (sc->recursive && isDirectory(path).ok()) {
      LOG(WARNING) << " collecting children of " << path << " to monitor";
      auto tp_iter = tracked_parent_dirs.find(fileRefNumber);
      if (tp_iter == tracked_parent_dirs.end())
      {
        tracked_parent_dirs[fileRefNumber] = {path, {std::make_pair(sc, std::string("*") ) } };
      }
      else
      {
        tp_iter->second.subscriptions.insert(std::make_pair(sc, std::string("*")));
      }

      std::vector<std::string> children;
      // Get a list of children of this directory (requested recursive watches).
      listDirectoriesInDirectory(path, children, true);

      boost::system::error_code ec;
      for (const auto& child : children) {
        auto canonicalized = fs::canonical(child, ec).string();
        addMonitor(canonicalized, sc);
      }
    }

    return true;
  }

  bool FileEventPublisher::addParentMonitor(const std::string &path, const std::string &filter, WindowsFileEventSubscriptionContextRef& sc)
  {
    LOG(WARNING) << "addMonitor(" << path << ")";
    if (FALSE == ::PathFileExistsA(path.c_str())) {
      LOG(WARNING) << "Path not found: " << path.c_str() << " " << ::GetLastError();
      return false;
    }

    DWORDLONG fileRefNumber = 0;
    if (!get_file_ref_number(path, fileRefNumber))
    {
      LOG(WARNING) << "Could not get file reference number: " << path.c_str() << " " << ::GetLastError();
      return false;
    }

    addVolume(path[0]);

    auto tp_iter = tracked_parent_dirs.find(fileRefNumber);
    if (tp_iter == tracked_parent_dirs.end())
    {
      tracked_parent_dirs[fileRefNumber] = {path, {std::make_pair(sc, std::string("*") ) } };
    }
    else
    {
      tp_iter->second.subscriptions.insert(std::make_pair(sc, std::string("*") ));
    }
    return true;
  }

  bool FileEventPublisher::monitorSubscription(WindowsFileEventSubscriptionContextRef &sc) {
    std::string discovered = sc->path;

    bool monitor_parent_dir = false;
    if (discovered.back() == '/') {
      discovered += "*";
    }

    if (sc->path.find("**") != std::string::npos) {
      sc->recursive = true;
      discovered = sc->path.substr(0, sc->path.find("**"));
      sc->path = discovered;
    } 

    if (sc->path.find('*') != std::string::npos) {
      // If the wildcard exists within the file (leaf), remove and monitor the
      // directory instead. Apply a fnmatch on fired events to filter leafs.

      std::string filter = "*";

      auto fullpath = fs::path(sc->path);
      if (fullpath.filename().string().find('*') != std::string::npos) {
        filter = fullpath.filename().string();
        monitor_parent_dir = true;
        LOG(WARNING) << "filter is \"" << filter << "\"";
      }
      std::vector<std::string> paths;
      resolveFilePattern(fullpath.string(), paths);
      for (const auto& _path : paths) {
        LOG(WARNING) << "adding monitor for " << _path ;
        addMonitor(_path, sc);
        if (isDirectory(_path).ok()) {
          LOG(WARNING) << "adding parent monitor for " << _path << " with filter " << filter;
          addParentMonitor(_path, filter, sc);
        }
      }
      if (monitor_parent_dir) {
        LOG(WARNING) << "adding parent monitor for " << fullpath.parent_path().string() << " with filter " << filter;
        addParentMonitor(fullpath.parent_path().string(), filter, sc);
      }
      return true;
    }

    return addMonitor(discovered, sc);
  }

  void FileEventPublisher::configure() {

    //TODO: delete all current subscriptions
    //then go through subscriptions_ and add them in
    //take a look at the inotify configure to get it right
    //

    for (auto &sub : subscriptions_) {
      monitorSubscription(getSubscriptionContext(sub->context));
    }

  }

  Status FileEventPublisher::setUp() {
    WriteLock(_scratch_mutex);
    _scratch = (char*)malloc(BUF_LEN);
    if (nullptr == _scratch) {
      LOG(WARNING) << "Could not allocate scratch space";
      return Status(1, "Could not allocate scratch space");
    }

    return Status(0, "OK");
  }

  void FileEventPublisher::tearDown() {
    WriteLock(_scratch_mutex);
    free(_scratch);
    _scratch = nullptr;
  }

  std::string create_full_path(std::string &parent_path, USN_RECORD *record)
  {
        char buffer[1024];
        sprintf_s(buffer, 1024, "%s/%.*S", parent_path.c_str(), record->FileNameLength/2, record->FileName);
        return std::string(buffer);
  }

  BOOL filter_matches(const std::string &filter, USN_RECORD *record)
  {
        char buffer[1024];
        sprintf_s(buffer, 1024, "%.*S", record->FileNameLength/2, record->FileName);
        return PathMatchSpecA(buffer, filter.c_str());
  }

  void FileEventPublisher::process_usn_record(USN_RECORD *record) {
    auto tf_iter = tracked_files.find(record->FileReferenceNumber);
    if (tracked_files.end() != tf_iter) {
      //fire event
      if (record->Reason & USN_REASON_RENAME_NEW_NAME)
      {
        auto parent_path = fs::path(tf_iter->second.path).parent_path().string();
        tf_iter->second.path = create_full_path(parent_path, record);
      }

      auto ec = createEventContext();
      ec->record = *record;
      ec->path = tf_iter->second.path;
      ec->action = record->Reason;
      for (auto &sub : tf_iter->second.subscriptions) {
        ec->sub_ctx = sub;
        fire(ec);
      }

      if (record->Reason & USN_REASON_FILE_DELETE) {
        tracked_files.erase(record->FileReferenceNumber);
      }
      return;
    }


    if (record->Reason & USN_REASON_FILE_CREATE) {
      auto parent_dir_iter = tracked_parent_dirs.find(record->ParentFileReferenceNumber);
      if (tracked_parent_dirs.end() != parent_dir_iter) {
        std::string full_path = create_full_path(parent_dir_iter->second.path, record);

        //add file into to tracked files
        for (auto &sub : parent_dir_iter->second.subscriptions) {
          if (filter_matches(sub.second, record)) {
            tf_iter = tracked_files.find(record->FileReferenceNumber);
            if (tf_iter == tracked_files.end()) {
              tracked_files[record->FileReferenceNumber] = { full_path, { sub.first } } ;
            }
            else
            {
              tf_iter->second.subscriptions.insert(sub.first);
            }
            auto ec = createEventContext();
            ec->record = *record;
            ec->path = full_path;
            ec->action = record->Reason;
            ec->sub_ctx = sub.first;
            fire(ec);
          }
        }
      }
    }
  }

  Status FileEventPublisher::run() {
    HANDLE hVol;

    USN_JOURNAL_DATA JournalData;
    READ_USN_JOURNAL_DATA ReadData = {0, 0xFFFFFFFF, FALSE, 0, 0};
    PUSN_RECORD UsnRecord;

    DWORD dwBytes;
    DWORD dwRetBytes;

    for (auto &vol : data->volumes) {
      char *volumePath = "\\\\.\\c:";
      volumePath[5] = vol.first;
      hVol = ::CreateFile( volumePath,
          GENERIC_READ | GENERIC_WRITE, 
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          NULL,
          OPEN_EXISTING,
          0,
          NULL);

      if( hVol == INVALID_HANDLE_VALUE ) {
        LOG(WARNING) << "CreateFile failed: " << GetLastError();
        break;
      }

      if( !::DeviceIoControl( hVol, 
            FSCTL_QUERY_USN_JOURNAL, 
            NULL,
            0,
            &JournalData,
            sizeof(JournalData),
            &dwBytes,
            NULL) )
      {
        LOG(WARNING) << "Query journal failed: " <<  GetLastError();
        return Status(1, "Query journal failed");
      }

      ReadData.StartUsn = vol.second;
      ReadData.UsnJournalID = JournalData.UsnJournalID;
      ReadData.MinMajorVersion = 2;
      ReadData.MaxMajorVersion = 2;

      {
        WriteLock(_scratch_mutex);
        for(;;) {
          memset( _scratch, 0, BUF_LEN );

          if( !::DeviceIoControl( hVol, 
                FSCTL_READ_USN_JOURNAL, 
                &ReadData,
                sizeof(ReadData),
                _scratch,
                BUF_LEN,
                &dwBytes,
                NULL) )
          {
            LOG(WARNING) << "Read journal failed: " << GetLastError();
            break;
          }

          dwRetBytes = dwBytes - sizeof(USN);

          if (dwRetBytes == 0) {
            //no new records, break
            vol.second = ReadData.StartUsn;
            break;
          }

          // Find the first record
          UsnRecord = (PUSN_RECORD)(((PUCHAR)_scratch) + sizeof(USN));  

          while( dwRetBytes > 0 ) {

            process_usn_record(UsnRecord);

            dwRetBytes -= UsnRecord->RecordLength;

            // Find the next record
            UsnRecord = (PUSN_RECORD)(((PCHAR)UsnRecord) + UsnRecord->RecordLength); 
          }
          // Update starting USN for next call
          ReadData.StartUsn = *(USN *)_scratch; 
        }
      }

      ::CloseHandle(hVol);
    }
    return Status(0, "OK");
  }

}
