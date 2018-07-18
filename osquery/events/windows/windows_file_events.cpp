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

  void FileEventPublisher::removeSubscriptions(const std::string& subscriber) {
    WriteLock lock(subscription_lock_);
    std::for_each(subscriptions_.begin(),
        subscriptions_.end(),
        [&subscriber](const SubscriptionRef& sub) {
        if (sub->subscriber_name == subscriber) {
        getSubscriptionContext(sub->context)->mark_for_deletion =
        true;
        }
        });
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

  bool FileEventPublisher::addMonitor(const std::string &path, WindowsFileEventSubscriptionContextRef& sc, bool descend)
  {
    if (FALSE == ::PathFileExistsA(path.c_str())) {
      LOG(WARNING) << "Path not found: " << path.c_str() << " " << ::GetLastError();
      return false;
    }

    DWORDLONG fileRefNumber = 0;
    DWORDLONG parentFileRefNumber = 0;
    if (!get_file_ref_number(path, fileRefNumber))
    {
      LOG(WARNING) << "Could not get file reference number: " << path.c_str() << " " << ::GetLastError();
      return false;
    }

    if (!get_file_ref_number(fs::path(path).parent_path().string(), parentFileRefNumber)) {
      LOG(WARNING) << "Could not get parent file reference number: " << path.c_str() << " " << ::GetLastError();
      return false;
    }

    addVolume(path[0]);

    insert_tracked_file(fileRefNumber, path, parentFileRefNumber, sc);

    if (sc->recursive && isDirectory(path).ok()) {

      insert_tracked_parent_dir(fileRefNumber, path, sc, std::string("*"));

      std::vector<std::string> children;
      // Get a list of children of this directory (requested recursive watches).
      listFilesInDirectory(path, children, true);

      boost::system::error_code ec;
      for (const auto& child : children) {
        auto canonicalized = fs::canonical(child, ec).string();
        LOG(WARNING) << "about to call addMonitor on child file " << child;
        addMonitor(canonicalized, sc);
      }
    }

    return true;
  }

  void FileEventPublisher::insert_tracked_parent_dir(DWORDLONG fileRefNumber, const std::string &path, const WindowsFileEventSubscriptionContextRef &sc, const std::string &filter)
  {
    auto tp_iter = tracked_parent_dirs.find(fileRefNumber);
    if (tp_iter == tracked_parent_dirs.end())
    {
      tracked_parent_dirs[fileRefNumber] = { path, { std::make_pair(sc, filter) } };
    }
    else
    {
      tp_iter->second.subscriptions.insert(std::make_pair(sc, filter) );
    }
  }

  void FileEventPublisher::insert_tracked_file(DWORDLONG fileRef, const std::string &path, DWORDLONG parentRef, const WindowsFileEventSubscriptionContextRef &sc) {
    auto tf_iter = tracked_files.find(fileRef);
    if (tf_iter == tracked_files.end()) {
      tracked_files[fileRef] = { path, parentRef, { sc } } ;
    }
    else
    {
      tf_iter->second.subscriptions.insert(sc);
    }
  }

  bool FileEventPublisher::addParentMonitor(const std::string &path, const std::string &filter, WindowsFileEventSubscriptionContextRef& sc)
  {
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

    insert_tracked_parent_dir(fileRefNumber, path, sc, filter);

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
      discovered = sc->path.substr(0, sc->path.find("**") + 1); //keep the last * as a wildcard
      sc->path = discovered;
    } 

    if (sc->path.find('*') != std::string::npos) {

      std::string filter = "*";

      auto fullpath = fs::path(sc->path);
      if (fullpath.filename().string().find('*') != std::string::npos) {
        filter = fullpath.filename().string();
        monitor_parent_dir = true;
      }
      std::vector<std::string> paths;
      resolveFilePattern(fullpath.string(), paths);
      for (const auto& _path : paths) {
        addMonitor(_path, sc, sc->recursive);
        if (isDirectory(_path).ok()) {
          addParentMonitor(_path, filter, sc);
        }
      }
      if (monitor_parent_dir) {
        std::vector<std::string> paths;
        resolveFilePattern(fullpath.parent_path().string(), paths);
        for (const auto& _path : paths) {
          if (isDirectory(_path).ok()) {
            addParentMonitor(_path, filter, sc);
          }
        }
      }
      return true;
    }

    return addMonitor(discovered, sc, sc->recursive);
  }

  void FileEventPublisher::configure() {

    SubscriptionVector delete_subscriptions; 
    { 
      WriteLock lock(subscription_lock_);
      auto end = std::remove_if(
          subscriptions_.begin(),
          subscriptions_.end(),
          [&delete_subscriptions](const SubscriptionRef& subscription) {
          auto sc = getSubscriptionContext(subscription->context);
          if (sc->mark_for_deletion == true) {
          delete_subscriptions.push_back(subscription);
          return true;
          }
          return false;
          });
      subscriptions_.erase(end, subscriptions_.end());
    }

    {
      WriteLock(_tracking_data_mutex);
      for (auto &tf = tracked_files.begin(); tf != tracked_files.end(); ) {
        for (auto sub_iter = tf->second.subscriptions.begin(); sub_iter != tf->second.subscriptions.end();) {
          if ((*sub_iter)->mark_for_deletion) {
            sub_iter = tf->second.subscriptions.erase(sub_iter);
          } else {
            sub_iter++;
          }
        }
        if (tf->second.subscriptions.empty()) {
          tf = tracked_files.erase(tf);
        } else {
          tf++;
        }
      }

      for (auto &tp = tracked_parent_dirs.begin(); tp != tracked_parent_dirs.end(); ) {
        for (auto sub_iter = tp->second.subscriptions.begin(); sub_iter != tp->second.subscriptions.end();) {
          if (sub_iter->first->mark_for_deletion) {
            sub_iter = tp->second.subscriptions.erase(sub_iter);
          } else {
            sub_iter++;
          }
        }
        if (tp->second.subscriptions.empty()) {
          tp = tracked_parent_dirs.erase(tp);
        } else {
          tp++;
        }
      }

    }

    delete_subscriptions.clear();

    {
      WriteLock(_tracking_data_mutex);
      for (auto &sub : subscriptions_) {
        monitorSubscription(getSubscriptionContext(sub->context));
      }
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
        sprintf_s(buffer, 1024, "%.*S", record->FileNameLength/2, record->FileName);
        std::stringstream sstream;
        sstream << parent_path;
        if (parent_path.back() != '/' && parent_path.back() != '\\') {
          sstream << '/';
        }
        sstream << buffer;
        return sstream.str();
  }

  BOOL filter_matches(const std::string &filter, USN_RECORD *record)
  {
        char buffer[1024];
        sprintf_s(buffer, 1024, "%.*S", record->FileNameLength/2, record->FileName);
        return PathMatchSpecA(buffer, filter.c_str());
  }

  std::string collect_path_from_file_id(DWORDLONG fileReferenceNumber)
  {
    HANDLE hint = ::CreateFile(".",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);
    if (hint == INVALID_HANDLE_VALUE) {
      LOG(WARNING) << "Unable to get handle to local directory: " << GetLastError();
      return "";
    }

    FILE_ID_DESCRIPTOR id_descriptor;
    id_descriptor.Type = (FILE_ID_TYPE)0;
    id_descriptor.FileId.QuadPart = fileReferenceNumber;

    HANDLE hFile = OpenFileById(hint, &id_descriptor, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, FILE_FLAG_BACKUP_SEMANTICS);
    CloseHandle(hint);

    if (hFile == INVALID_HANDLE_VALUE) {
      LOG(WARNING) << "Unable to get handle to moved file : " << GetLastError();
      return "";
    }

    char buffer[MAX_PATH];
    auto rc = GetFinalPathNameByHandleA(hFile, buffer, MAX_PATH, 0);
    CloseHandle(hFile);
    if (rc > 0) {
      return fs::path(&buffer[4]).string();
    }

    LOG(WARNING) << "Unable to get final path name for moved file: " << GetLastError();
    return "";
  

  }

  void FileEventPublisher::process_usn_record(USN_RECORD *record) {
    WriteLock(_tracking_data_mutex);

    auto tf_iter = tracked_files.find(record->FileReferenceNumber);
    if (tracked_files.end() != tf_iter) {

      if (record->Reason & USN_REASON_RENAME_NEW_NAME)
      {
        if (record->ParentFileReferenceNumber != tf_iter->second.parent_file_reference)
        {
          //moved to a new directory.
          //remove any old subscriptions that are directory based
          auto tp_iter = tracked_parent_dirs.find(tf_iter->second.parent_file_reference);
          if (tp_iter != tracked_parent_dirs.end())
          {
            for (auto &sub : tp_iter->second.subscriptions) {
              tf_iter->second.subscriptions.erase(sub.first);
            }
          }

          tf_iter->second.parent_file_reference = record->ParentFileReferenceNumber;

          //check to see if the resulting directory has a matching subsciption
          tp_iter = tracked_parent_dirs.find(record->ParentFileReferenceNumber);
          if (tp_iter != tracked_parent_dirs.end())
          {
            std::string full_path = create_full_path(tp_iter->second.path, record);
            tf_iter->second.path = full_path;

            //add additional subscription data to file tracking
            for (auto &sub : tp_iter->second.subscriptions) {
              if (filter_matches(sub.second, record)) {
                tf_iter = tracked_files.find(record->FileReferenceNumber);
                tf_iter->second.subscriptions.insert(sub.first);
              }
            }
          }
          else
          {
            //if the file was tracked directly, we'll keep watching
            //moved out of a monitored directory into an unmonitored one, no more tracking?
            if (tf_iter->second.subscriptions.empty())
            {
              tracked_files.erase(tf_iter);
              return;
            }
            //otherwise we need to work out what the file's new path is
            auto new_path = collect_path_from_file_id(record->FileReferenceNumber);
            tf_iter->second.path = new_path;
          }


        }
        else{
          auto parent_path = fs::path(tf_iter->second.path).parent_path().string();
          tf_iter->second.path = create_full_path(parent_path, record);
        }
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


    //for all created files, check if they're in a directory we're tracking
    if (record->Reason & USN_REASON_FILE_CREATE) {
      auto parent_dir_iter = tracked_parent_dirs.find(record->ParentFileReferenceNumber);
      if (tracked_parent_dirs.end() != parent_dir_iter) {
        std::string full_path = create_full_path(parent_dir_iter->second.path, record);

        bool directory = isDirectory(full_path).ok();
        //add file into to tracked files
        for (auto &sub : parent_dir_iter->second.subscriptions) {
          if (filter_matches(sub.second, record)) {
            insert_tracked_file(record->FileReferenceNumber, full_path, record->ParentFileReferenceNumber, sub.first);
            if (sub.first->recursive && directory) {
              insert_tracked_parent_dir(record->FileReferenceNumber, full_path, sub.first, std::string("*"));
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
