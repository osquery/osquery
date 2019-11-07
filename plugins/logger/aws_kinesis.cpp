/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "aws_kinesis.h"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <thread>

#include <aws/core/client/AWSError.h>
#include <aws/core/utils/Outcome.h>
#include <aws/kinesis/model/PutRecordsRequest.h>
#include <aws/kinesis/model/PutRecordsResult.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/process/process.h>
#include <osquery/registry.h>
#include <osquery/system.h>

#include <osquery/utils/aws/aws_util.h>

namespace fs = boost::filesystem;

#ifdef WIN32
#undef GetMessage
#endif

// If there are AWS errors, refresh the handle, which may pull in newer
// FLAGS_aws_xx config such as the sts token.  But not more often than
// AWS_HANDLE_REFRESH_SECONDS

#define AWS_HANDLE_REFRESH_SECONDS 450 // 7.5 minutes (config refresh 5 mins)

namespace osquery {

DECLARE_string(aws_access_key_id);  // from aws_util.cpp
DECLARE_string(aws_session_token);

REGISTER(KinesisLoggerPlugin, "logger", "aws_kinesis");

FLAG(uint64,
     aws_kinesis_period,
     8,
     "Seconds between flushing logs to Kinesis (default 8)");

FLAG(string, aws_kinesis_stream, "", "Name of Kinesis stream for logging")

FLAG(bool,
     aws_kinesis_random_partition_key,
     false,
     "Enable random kinesis partition keys");

// Kinesis stream limit of 1000 records per second
FLAG(uint64,
     aws_kinesis_batch_max_records,
     500U,
     "Number of records per period");

FLAG(uint64, aws_kinesis_batch_max_bytes, 5000000U, "Max bytes per batch");

static bool gHaveSetup = false;

class KinesisForwarder : public Forwarder {
 public:
  KinesisForwarder(const LoggerBounds bounds)
      : Forwarder(bounds), linebuf_(bounds.max_bytes_per_record), _condition_lock(), _condition() {
    partition_key_ = getHostIdentifier();
  }
  virtual ~KinesisForwarder() {}

  Status send(std::string file_path) override {
    Aws::Vector<Aws::Kinesis::Model::PutRecordsRequestEntry> records;

    if (aws_id_changed() || client_ == nullptr) {
      if (!shouldResetAwsHandle()) {
        return Status(FORWARDER_STATUS_NO_CONNECTION);
      }
    }

    // parse file into records

    int readerr = _load(file_path, records);
    if (readerr != 0) {
      return Status(readerr, "Error reading file");
    }

    // build request

    Aws::Kinesis::Model::PutRecordsRequest request;
    request.WithStreamName(FLAGS_aws_kinesis_stream).SetRecords(records);

    // do the send, with some retries

    int retry;
    for (retry = 0; retry < 3; retry++) {
      if (retry > 0) {
	    _pause(std::chrono::milliseconds(100));
      }
      auto outcome = client_->PutRecords(request);

      if (outcome.IsSuccess()) {
        break;
      }

      int failedCount = outcome.GetResult().GetFailedRecordCount();
      if (failedCount > 0 && failedCount < (int)records.size()) {
        LOG(WARNING) << "partial failure: " << failedCount << " of " << records.size();

        // remove successful entries
        const std::vector<Aws::Kinesis::Model::PutRecordsResultEntry> &refResults = outcome.GetResult().GetRecords();
        auto it = records.begin();
        int numRecords = (int)records.size();
        for (int i = 0; i < numRecords; i++) {
          if (i >= (int)refResults.size()) {
            break; // just in case. results should match records.size
          }
          const Aws::Kinesis::Model::PutRecordsResultEntry &entry = refResults[i];
          const Aws::String & refEntryErrCode = entry.GetErrorCode();
          if (refEntryErrCode.empty()) {
            records.erase(it++);  // remove successful
          } else {
            it++;
          }
        }

        continue; // will retry
      }

      const Aws::Kinesis::KinesisErrors code = outcome.GetError().GetErrorType();

      // network connection down?

      if (code == Aws::Kinesis::KinesisErrors::NETWORK_CONNECTION) {
        return Status(FORWARDER_STATUS_NO_CONNECTION);
      }
      if (code == Aws::Kinesis::KinesisErrors::SLOW_DOWN) {
        LOG(WARNING) << "Received Kinesis SLOW_DOWN";
        _pause(std::chrono::milliseconds(500));
        return Status(FORWARDER_STATUS_NO_CONNECTION);
      }

      if (code == Aws::Kinesis::KinesisErrors::ACCESS_DENIED
          || code == Aws::Kinesis::KinesisErrors::MISSING_AUTHENTICATION_TOKEN) {
        client_ = nullptr;
        LOG(WARNING) << "kinesis access denied. clearing handle";
        return Status(FORWARDER_STATUS_NO_CONNECTION);
      }

      // anything we can retry?

      if (code == Aws::Kinesis::KinesisErrors::REQUEST_EXPIRED
          || code == Aws::Kinesis::KinesisErrors::INTERNAL_FAILURE) {
        LOG(WARNING) << "kinesis failed with code:" << std::to_string((uint32_t)code);
        continue;
      }

      // any other error probably can't be fixed by retry
      LOG(ERROR) << "send fail. Code:" << (uint32_t)code << " msg:" << outcome.GetError().GetMessage();

      // invalidate handle because:
      //   Sometimes get code==UNKNOWN error with ExpiredTokenException in the
      //   message string rather than code == ACCESS_DENIED

      client_ = nullptr;

      return Status((int)code, "error in send");
    }

    if (retry >= 3) {
      return Status(1, "Failed with retries");
    }

    return Status();
  }

  /**
   * keeps track of FLAGS_aws_access_key_id, return true if changed.
   */
  bool aws_id_changed() {
    static std::string last_aws_access_key;
    static std::string last_aws_session_token;

    if (last_aws_access_key != FLAGS_aws_access_key_id
        || last_aws_session_token != FLAGS_aws_session_token ) {
      VLOG(1) << "using new aws access key:" << FLAGS_aws_access_key_id;
      last_aws_access_key = FLAGS_aws_access_key_id;
      last_aws_session_token = FLAGS_aws_session_token;
      return true;
    }

    return false;
  }

  /*
   * This should only be called when there was a send error.
   * This will call makeAWSClient(client_) to obtain a new
   * handle with latest FLAGS , in case there was a config change
   * for IAM role, etc.
   */
  bool shouldResetAwsHandle() {
    static time_t tLastReset = 0;
    time_t now = time(NULL);
    if ((now - tLastReset) >= AWS_HANDLE_REFRESH_SECONDS) {
      tLastReset = now;
      VLOG(1) << "obtaining new AWS client handle.";
      Status s = makeAWSClient<Aws::Kinesis::KinesisClient>(client_);
      return s.ok();
    }
    return false;
  }

  /*
   * read file lines, populate records.
   * returns false on success, true on error.
   */
  int _load(
      std::string file_path,
      Aws::Vector<Aws::Kinesis::Model::PutRecordsRequestEntry>& records) {
    file_path = fs::path(file_path).make_preferred().string();

    FILE* fp = FOPEN(file_path.c_str(), "r");
    if (fp == nullptr) {
      LOG(ERROR) << "unable to open cached log:" << file_path;
      return FORWARDER_STATUS_READ_ERROR;
    }

    while (nullptr != fgets(linebuf_.data(), (int)linebuf_.size(), fp)) {
      size_t len = strlen(linebuf_.data());
      if (len <= 1)
        continue;

      if (linebuf_.data()[0] == '#') {
        // metadata (TODO: check against MD5 of previous file)
        continue;
      }

      // adjust len to ignore trailing newline
      len--;

      // check for truncated msgs - expect valid JSON object
      if (linebuf_[len-1] != '}') {
        LOG(WARNING) << "Drop Truncated : (possibly due to watchdog kill):" << std::string(linebuf_.data());
        continue;
      }

      // Initialize and store the new log record
      auto buffer = Aws::Utils::ByteBuffer(
          reinterpret_cast<unsigned char*>(linebuf_.data()), len);

      auto idx = records.size();
      if (idx > bounds_.max_records_per_batch) {
        LOG(ERROR) << "cached log file failed bounds check idx:" << idx
                   << " max_records:" << bounds_.max_records_per_batch;
        break;
      }

      Aws::Kinesis::Model::PutRecordsRequestEntry aws_record;
      initializeRecord(aws_record, buffer);
      records.emplace_back(std::move(aws_record));
    }

    fclose(fp);

    if (records.empty()) {
      VLOG(1) << "no records in cached file? " << file_path;
      return FORWARDER_STATUS_EMPTY_FILE;
    }

    return 0;
  }

  Status setUp() {
    return Status();
  }

 protected:
  void initializeRecord(Aws::Kinesis::Model::PutRecordsRequestEntry& record,
                        Aws::Utils::ByteBuffer& buffer) const {
    std::string record_partition_key;
    if (FLAGS_aws_kinesis_random_partition_key) {
      // Generate a random partition key for each record, ensuring that
      // records are spread evenly across shards.
      boost::uuids::uuid uuid = boost::uuids::random_generator()();
      record_partition_key = boost::uuids::to_string(uuid);
    } else {
      record_partition_key = partition_key_;
    }

    record.WithPartitionKey(record_partition_key).WithData(buffer);
  }

  void _pause(std::chrono::milliseconds milli) {
	  std::unique_lock<std::mutex> lock(_condition_lock);
	  _condition.wait_for(lock, milli);
  }

  std::vector<char> linebuf_;
  std::shared_ptr<Aws::Kinesis::KinesisClient> client_{nullptr};
  std::mutex _condition_lock;
  std::condition_variable _condition;
  std::string partition_key_;
};

Status KinesisLoggerPlugin::setUp() {
  if (!gHaveSetup) {
    gHaveSetup = true;
    LoggerBounds bounds;
    bounds.max_records_per_batch = FLAGS_aws_kinesis_batch_max_records;
    bounds.max_bytes_per_record = 1000000 - 256;
    bounds.max_bytes_per_batch = FLAGS_aws_kinesis_batch_max_bytes;

    setProps("aws_kinesis", true, bounds);

    initAwsSdk();

    auto forwarder = std::make_shared<KinesisForwarder>(bounds);
    Status s = forwarder->setUp();
    if (!s.ok()) {
      LOG(ERROR) << "Error initializing Kinesis logger: " << s.getMessage();
      return s;
    }

    start(forwarder, (uint32_t)FLAGS_aws_kinesis_period, 4, 1250);
  }

  return Status(0, "OK");
}

void KinesisLoggerPlugin::init(const std::string& name,
                               const std::vector<StatusLogLine>& log) {
  logStatus(log);
}

} // namespace osquery
