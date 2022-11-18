/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/windows/etw/etw_post_processing_pipeline.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/map_take.h>
#include <osquery/utils/status/status.h>

namespace osquery {

EtwPostProcessorsRunnable::EtwPostProcessorsRunnable(
    const std::string& sessionName, ConcurrentEventQueueRef& sharedQueue)
    : InternalRunnable(sessionName), concurrentQueue_(sharedQueue) {}

EtwPostProcessorsRunnable::~EtwPostProcessorsRunnable() {
  stop();
}

Status EtwPostProcessorsRunnable::addProvider(
    const EtwProviderConfig& configData) {
  // Sanity check on input ETW Provider configuration data
  Status validProvider = configData.isValid();
  if (!validProvider.ok()) {
    return Status::failure("Invalid ETW provider data: " +
                           validProvider.getMessage());
  }

  // Adding post processor callback to callbacks collection
  for (const EtwEventType& eventType : configData.getEventTypes()) {
    etwPostProcessors_.insert({eventType, configData.getPostProcessor()});
  }

  return Status::success();
}

bool EtwPostProcessorsRunnable::CommonPostProcessing(EtwEventDataRef& data) {
  // Osquery timestamp
  FILETIME workTime{0};
  workTime.dwLowDateTime = data->Header.RawHeader.TimeStamp.LowPart;
  workTime.dwHighDateTime = data->Header.RawHeader.TimeStamp.HighPart;
  data->Header.UnixTimestamp = filetimeToUnixtime(workTime);

  // Human UTC timestamp
  std::time_t datetime = data->Header.UnixTimestamp;
  tm tmTimeData{0};
  if ((gmtime_s(&tmTimeData, &datetime) != 0) || (tmTimeData.tm_year == 0)) {
    return false;
  }
  std::stringstream dumpTimestamp;
  dumpTimestamp << std::put_time(&tmTimeData, "%Y-%m-%d %H:%M:%S UTC");
  data->Header.DateTime.assign(dumpTimestamp.str());

  // Windows timestamp in 100 nanoseconds resolution
  data->Header.WinTimestamp = data->Header.RawHeader.TimeStamp.QuadPart;

  // Header type description update
  data->Header.TypeInfo = tryTakeCopy(kEtwEventTypeStrings, data->Header.Type)
                              .takeOr(std::string("Invalid"));

  return true;
}

void EtwPostProcessorsRunnable::start() {
  while (!interrupted()) {
    // Worker will blockwait until a new element is retrieved from the queue
    auto data = concurrentQueue_->pop();

    // Common post processing on every ETW event
    if (!CommonPostProcessing(data)) {
      return;
    }

    // Event specific post processing callback logic
    auto postProcessorFn =
        tryTakeCopy(etwPostProcessors_, data->Header.Type)
            .takeOr(EtwProviderConfig::EventProviderPostProcessor{nullptr});

    // callback was found for given event type id
    if (postProcessorFn) {
      postProcessorFn(data);
    }
  }
}

void EtwPostProcessorsRunnable::stop() {
  interrupt();
}
} // namespace osquery