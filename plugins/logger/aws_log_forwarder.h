/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include "plugins/logger/buffered.h"

#include <chrono>
#include <memory>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/plugins/logger.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/logger/logger.h>

#include <osquery/utils/aws/aws_util.h>

namespace osquery {
template <typename RecordType,
          typename ClientType,
          typename OutcomeType,
          typename ResultType>
class AwsLogForwarder : public BufferedLogForwarder {
 public:
  using Outcome = OutcomeType;
  using Client = ClientType;
  using Record = RecordType;
  using Batch = std::vector<RecordType>;
  using BatchList = std::vector<Batch>;
  using Result = ResultType;

 public:
  AwsLogForwarder(const std::string& name,
                  size_t log_period,
                  size_t max_lines,
                  const std::string& endpoint_override)
      : BufferedLogForwarder(std::string("AwsLogForwarder:") + name,
                             name,
                             std::chrono::seconds(log_period),
                             max_lines),
        name_(name),
        endpoint_override_(endpoint_override) {}

  /// Common plugin initialization
  Status setUp() override {
    Status s = BufferedLogForwarder::setUp();
    if (!s.ok()) {
      return s;
    }

    s = makeAWSClient<Client>(client_, "", true, endpoint_override_);
    if (!s.ok()) {
      return s;
    }

    return internalSetup();
  }

 private:
  /// Dumps the given batch to the error log
  void dumpBatchToErrorLog(const Batch& batch) const {
    std::stringstream error_output;

    error_output << name_
                 << " logger: Failed to write the following records:\n";
    dumpBatch(error_output, batch);

    LOG(ERROR) << error_output.str();
  }

  /// Dumps the discarded records to the error log
  void dumpDiscardedRecordsToErrorLog(
      const std::vector<std::string>& discarded_records) const {
    if (discarded_records.empty()) {
      return;
    }

    std::stringstream output;
    output << name_ << ": The following log records have been discarded "
                       "because they were too big:\n";

    for (const auto& record : discarded_records) {
      output << record << "\n";
    }

    LOG(ERROR) << output.str();
  }

  /// Dumps the specified batch to the given stream
  std::ostream& dumpBatch(std::ostream& stream, const Batch& batch) const {
    size_t index = 0;

    for (auto it = batch.begin(); it != batch.end(); it++) {
      const auto& record = *it;
      const auto& raw_buffer = record.GetData();

      index++;

      std::string buffer(
          reinterpret_cast<const char*>(raw_buffer.GetUnderlyingData()),
          raw_buffer.GetLength());
      stream << "Record #" << index << ": " << buffer;

      if (std::next(it, 1) != batch.end()) {
        stream << "\n";
      }
    }

    return stream;
  }

  /// Consumes the specified log records generating one or more batches
  BatchList consumeDataAndGenerateBatches(
      std::vector<std::string>& discarded_records,
      const std::string& log_type,
      std::vector<std::string>& log_data) const {
    BatchList batch_list;

    Batch current_batch;
    size_t current_batch_byte_size = 0U;

    for (auto& record : log_data) {
      // Initialize the line and make sure we are still within protocol limits
      Status status = appendLogTypeToJson(log_type, record);
      if (!status.ok()) {
        // To achieve behavior parity with TLS logger plugin, skip non-JSON
        // content
        LOG(ERROR) << name_ << ": The following log record has been discarded "
                               "because it was not in JSON format: "
                   << record;

        continue;
      }

      size_t record_size = record.size();
      if (appendNewlineSeparators()) {
        ++record_size;
      }

      if (record_size >= getMaxBytesPerRecord() ||
          record_size >= getMaxBytesPerBatch()) {
        discarded_records.push_back(std::move(record));
        continue;
      }

      // Complete the current batch if it's full
      if (current_batch_byte_size + record_size >= getMaxBytesPerBatch() ||
          (current_batch.size() >= getMaxRecordsPerBatch())) {
        batch_list.push_back(current_batch);

        current_batch.clear();
        current_batch_byte_size = 0U;
      }

      // Initialize and store the new log record
      auto buffer = Aws::Utils::ByteBuffer(
          reinterpret_cast<unsigned char*>(&record[0]), record_size);

      if (appendNewlineSeparators()) {
        buffer[record_size - 1] = '\n';
      }

      RecordType aws_record;
      initializeRecord(aws_record, buffer);

      current_batch.emplace_back(std::move(aws_record));
      current_batch_byte_size += record_size;
    }

    if (!current_batch.empty()) {
      batch_list.push_back(current_batch);
    }

    log_data.clear();
    return batch_list;
  }

 protected:
  /// Sends a single batch
  bool sendBatch(Batch& batch, std::stringstream& status_output) {
    bool success = false;

    auto max_retry_count = getMaxRetryCount();
    auto base_retry_delay = getInitialRetryDelay();

    for (size_t retry = 0; retry < max_retry_count; retry++) {
      bool is_last_retry = (retry + 1 >= max_retry_count);

      // Increase the resend delay at each retry
      size_t retry_delay =
          (retry == 0 ? 0 : base_retry_delay) + (retry * 1000U);
      if (retry_delay != 0) {
        pause(std::chrono::milliseconds(retry_delay));
      }

      // Attempt to send the batch
      auto outcome = internalSend(batch);

      size_t failed_record_count;
      bool request_failure;
      if (!outcome.IsSuccess()) {
        failed_record_count = batch.size();
        request_failure = true;
      } else {
        failed_record_count = getFailedRecordCount(outcome);
        request_failure = false;
      }

      size_t sent_record_count = batch.size() - failed_record_count;

      if (sent_record_count > 0) {
        VLOG(1) << name_ << ": Successfully sent "
                << batch.size() - failed_record_count << " out of "
                << batch.size() << " log records";
      }

      if (failed_record_count == 0) {
        success = true;
        break;
      }

      // Only log final errors
      if (is_last_retry) {
        if (!status_output.str().empty()) {
          status_output << "\n";
        }

        status_output << outcome.GetError().GetMessage();
      }

      // We didn't manage to send all records; remove the ones that succeeded
      // (so that we do not duplicate them) and try again
      if (request_failure) {
        // By default, we have a high maximum retry count value! The user will
        // not notice right away that his configuration is broken without this
        // message!
        LOG(ERROR) << name_ << ": Complete request failure: "
                   << outcome.GetError().GetMessage();
        continue;
      }

      const auto& result_record_list = getResult(outcome);

      for (size_t i = batch.size(); i-- > 0;) {
        if (!result_record_list[i].GetErrorCode().empty()) {
          continue;
        }

        auto it = std::next(batch.begin(), i);
        batch.erase(it);
      }
    }

    return success;
  }

  /// Sends the specified data in one or more batches, depending on the log size
  Status send(std::vector<std::string>& log_data,
              const std::string& log_type) override {
    // Generate the batches, according to the protocol limits
    std::vector<std::string> discarded_records;
    auto batch_list =
        consumeDataAndGenerateBatches(discarded_records, log_type, log_data);

    dumpDiscardedRecordsToErrorLog(discarded_records);
    discarded_records.clear();

    // Send each batch
    size_t error_count = 0;
    std::stringstream status_output;

    for (auto batch_it = batch_list.begin(); batch_it != batch_list.end();) {
      auto& batch = *batch_it;
      if (!sendBatch(batch, status_output)) {
        // We couldn't write some of the records; log them locally so that the
        // administrator will at least be able to inspect them
        dumpBatchToErrorLog(batch);
        error_count++;
      }

      batch_it = batch_list.erase(batch_it);
    }

    if (error_count != 0) {
      return Status(1, status_output.str());
    }

    return Status(0, "OK");
  }

  /// Plugin-specific initialization is performed here
  virtual Status internalSetup() = 0;

  /// Plugin-specific send method
  virtual Outcome internalSend(const Batch& batch) = 0;

  /// Plugin-specific record initialization is performed here
  virtual void initializeRecord(Record& record,
                                Aws::Utils::ByteBuffer& buffer) const = 0;

  /// Must return the amount of bytes that can fit in a single record
  virtual size_t getMaxBytesPerRecord() const = 0;

  /// Must return the amount of records that can be inserted into a single batch
  virtual size_t getMaxRecordsPerBatch() const = 0;

  /// Must return the amount of bytes that can fit in a single batch
  virtual size_t getMaxBytesPerBatch() const = 0;

  /// Must return the maximum amount of retries when sending records
  virtual size_t getMaxRetryCount() const = 0;

  /// Must return the initial delay, in seconds, between each retry
  virtual size_t getInitialRetryDelay() const = 0;

  /// Must return true if records should be terminated with newlines
  virtual bool appendNewlineSeparators() const = 0;

  /// Must return the amount of records that could not be sent
  virtual size_t getFailedRecordCount(Outcome& outcome) const = 0;

  /// Must return the vector containing the upload result for each record
  virtual Result getResult(Outcome& outcome) const = 0;

 protected:
  /// Plugin-specific service client
  std::shared_ptr<Client> client_{nullptr};

  /// Logger name; used when printing messages
  std::string name_;

  /// Service endpoint override
  std::string endpoint_override_;
};
}
