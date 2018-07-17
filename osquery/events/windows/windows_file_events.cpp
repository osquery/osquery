#include <string>
#include <sstream>

#include <shlwapi.h>

#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/events/windows/windows_file_events.h"

constexpr unsigned int BUF_LEN = 4096;

namespace osquery {

  REGISTER(FileEventPublisher, "event_publisher", "windows_file_events");

  struct FileEventPublisher::PrivateData final {
    std::map<char, USN> volumes;
  };

  bool get_file_ref_number(std::string &path, DWORDLONG &fileRefNumber)
  {
    HANDLE h = ::CreateFile(path.c_str(),
        GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (INVALID_HANDLE_VALUE == h) return false;

    BY_HANDLE_FILE_INFORMATION info;
    if (!::GetFileInformationByHandle(h, &info)) {
      ::CloseHandle(h);
      return false;
    }

    fileRefNumber = ((DWORDLONG)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    ::CloseHandle(h);
    return true;
  }

  FileEventPublisher::FileEventPublisher() : data(new PrivateData) {
  }

  Status FileEventPublisher::addSubscription(const SubscriptionRef &subscription) {
    LOG(WARNING) << "addSubscription()";
    auto received_subscription_ctx = getSubscriptionContext(subscription->context);
    if (FALSE == ::PathFileExistsA(received_subscription_ctx->path.c_str())) {
      LOG(WARNING) << "Path not found: " << received_subscription_ctx->path.c_str() << " " << ::GetLastError();
      return Status(1);
    }

    DWORDLONG fileRefNumber = 0;
    if (!get_file_ref_number(received_subscription_ctx->path, fileRefNumber))
    {
      LOG(WARNING) << "Could not get file reference number: " << received_subscription_ctx->path.c_str() << " " << ::GetLastError();
      return Status(1);
    }

    char volume = received_subscription_ctx->path[0];
    WriteLock(_private_data_mutex);
    auto search = data->volumes.find(volume);
    if (search == data->volumes.end())
    {
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
        return Status(1, "CreateFile failed");
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
        return Status(1, "Query journal failed");
      }

      data->volumes[volume] = JournalData.NextUsn;
    }

    tracked_files[fileRefNumber] = received_subscription_ctx->path;
    LOG(WARNING) << "added file with path " << received_subscription_ctx->path << " to tracked files";

    subscriptions_.push_back(subscription);
    LOG(WARNING) << "returning OK from AddSubscription";
    return Status(0, "OK");
  }

  void FileEventPublisher::configure() {
    //TODO: add logic to resolve paths and volumes of subsciptions here
  }

  Status FileEventPublisher::setUp() {
    LOG(WARNING) << "FileEventPublisher::setUp()" ; 
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

  void FileEventPublisher::process_usn_record(USN_RECORD *record) {
    /*
       printf( "USN: %I64x\n", record->Usn );
       printf("File name: %.*S\n", 
       record->FileNameLength/2, 
       record->FileName );
       printf( "Reason: %x\n", record->Reason );
       printf( "\n" );
       */
    if (tracked_files.end() != tracked_files.find(record->FileReferenceNumber)) {
      //fire event
      auto ec = createEventContext();
      ec->record = *record;
      ec->path = tracked_files[record->FileReferenceNumber];
      ec->action = record->Reason;

      //TODO: possibly add the subscription context?

      fire(ec);

      if (record->Reason & USN_REASON_FILE_DELETE) {
        //TODO:
        //remove the entry from the tracked_files list
      }
      return;
    }

    if (record->Reason & USN_REASON_FILE_CREATE) {
      if (tracked_parent_dirs.end() != tracked_parent_dirs.find(record->ParentFileReferenceNumber)) {
        //add file into to tracked files
        auto ec = createEventContext();
        ec->record = *record;
        ec->path = tracked_files[record->FileReferenceNumber];
        ec->action = record->Reason;
        fire(ec);
        return;
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
