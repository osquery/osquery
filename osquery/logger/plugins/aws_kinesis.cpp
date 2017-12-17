/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

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
#include <osquery/registry.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/logger/plugins/aws_kinesis.h"

namespace osquery {

REGISTER(KinesisLoggerPlugin, "logger", "aws_kinesis");

FLAG(uint64,
     aws_kinesis_period,
     10,
     "Seconds between flushing logs to Kinesis (default 10)");

FLAG(string, aws_kinesis_stream, "", "Name of Kinesis stream for logging")

FLAG(bool,
     aws_kinesis_random_partition_key,
     false,
     "Enable random kinesis partition keys");

Status KinesisLoggerPlugin::setUp() {
  initAwsSdk();
  forwarder_ = std::make_shared<KinesisLogForwarder>(
      "aws_kinesis", FLAGS_aws_kinesis_period, 500);
  Status s = forwarder_->setUp();
  if (!s.ok()) {
    LOG(ERROR) << "Error initializing Kinesis logger: " << s.getMessage();
    return s;
  }
  Dispatcher::addService(forwarder_);
  return Status(0, "OK");
}

Status KinesisLoggerPlugin::logString(const std::string& s) {
  return forwarder_->logString(s);
}

Status KinesisLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  return forwarder_->logStatus(log);
}

void KinesisLoggerPlugin::init(const std::string& name,
                               const std::vector<StatusLogLine>& log) {
  logStatus(log);
}

Status KinesisLogForwarder::internalSetup() {
  partition_key_ = getHostIdentifier();

  if (FLAGS_aws_kinesis_stream.empty()) {
    return Status(1, "Stream name must be specified with --aws_kinesis_stream");
  }

  VLOG(1) << "Kinesis logging initialized with stream: "
          << FLAGS_aws_kinesis_stream;

  return Status(0, "OK");
}

KinesisLogForwarder::Outcome KinesisLogForwarder::internalSend(
    const Batch& batch) {
  Aws::Kinesis::Model::PutRecordsRequest request;
  request.WithStreamName(FLAGS_aws_kinesis_stream).SetRecords(batch);
  return client_->PutRecords(request);
}

void KinesisLogForwarder::initializeRecord(
    Record& record, Aws::Utils::ByteBuffer& buffer) const {
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

size_t KinesisLogForwarder::getMaxBytesPerRecord() const {
  // Max size of log + partition key is 1MB. Max size of partition key is 256B.
  return (1000000U - 256U);
}

size_t KinesisLogForwarder::getMaxRecordsPerBatch() const {
  return 500U;
}

size_t KinesisLogForwarder::getMaxBytesPerBatch() const {
  return 5000000U;
}

size_t KinesisLogForwarder::getMaxRetryCount() const {
  return 100U;
}

size_t KinesisLogForwarder::getInitialRetryDelay() const {
  return 3000U;
}

bool KinesisLogForwarder::appendNewlineSeparators() const {
  return false;
}

size_t KinesisLogForwarder::getFailedRecordCount(Outcome& outcome) const {
  return static_cast<size_t>(outcome.GetResult().GetFailedRecordCount());
}

KinesisLogForwarder::Result KinesisLogForwarder::getResult(
    Outcome& outcome) const {
  return outcome.GetResult().GetRecords();
}
}
