/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <variant>

#include <osquery/core/flags.h>
#include <osquery/events/events.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/events/windows/etw_process_events.h>

namespace osquery {

REGISTER_ETW_SUBSCRIBER(EtwProcessEventSubscriber, "etw_process_events");
DECLARE_bool(enable_etw_process_events);

Status EtwProcessEventSubscriber::init() {
  if (!FLAGS_enable_etw_process_events) {
    return Status::failure("subscriber disabled via configuration.");
  }
  auto subscription_context = createSubscriptionContext();
  subscribe(&EtwProcessEventSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status EtwProcessEventSubscriber::eventCallback(
    const ECRef& event_context, const SCRef& event_subscription) {
  if ((!event_context) || (!event_context->data)) {
    return Status::failure("Invalid event context");
  }

  // New event row to capture the incoming ETW event data
  Row newRow;

  // Sugar syntax to facilitate the access to the event header
  const auto& eventHeader = event_context->data->Header;

  // Common fields
  newRow["type"] = SQL_TEXT(eventHeader.TypeInfo);
  newRow["datetime"] = BIGINT(eventHeader.UnixTimestamp);
  newRow["time_windows"] = BIGINT(eventHeader.WinTimestamp);
  newRow["header_pid"] = BIGINT(eventHeader.RawHeader.ProcessId);

  if (eventHeader.Type == EtwEventType::ProcessStart) {
    // Process start events handling

    if (!std::holds_alternative<EtwProcStartDataRef>(
            event_context->data->Payload)) {
      return Status::failure("Invalid event payload");
    }

    // Sugar syntax to facilitate the access to the event payload
    const auto& eventPayload =
        std::get<EtwProcStartDataRef>(event_context->data->Payload);

    if (!eventPayload) {
      return Status::failure("Event payload was null");
    }

    newRow["pid"] = BIGINT(eventPayload->ProcessId);
    newRow["ppid"] = BIGINT(eventPayload->ParentProcessId);
    newRow["session_id"] = INTEGER(eventPayload->SessionId);
    newRow["flags"] = INTEGER(eventPayload->Flags);
    newRow["path"] = SQL_TEXT(eventPayload->ImageName);
    newRow["cmdline"] = SQL_TEXT(eventPayload->Cmdline);
    newRow["username"] = SQL_TEXT(eventPayload->UserName);
    newRow["token_elevation_type"] =
        SQL_TEXT(eventPayload->TokenElevationTypeInfo);
    newRow["token_elevation_status"] = INTEGER(eventPayload->TokenIsElevated);
    newRow["mandatory_label"] = SQL_TEXT(eventPayload->MandatoryLabelSid);
    newRow["process_sequence_number"] =
        BIGINT(eventPayload->ParentProcessSequenceNumber);
    newRow["parent_process_sequence_number"] =
        BIGINT(eventPayload->ParentProcessSequenceNumber);

    std::vector<Row> rowList;
    rowList.push_back(std::move(newRow));
    addBatch(rowList, eventHeader.UnixTimestamp);

  } else if (eventHeader.Type == EtwEventType::ProcessStop) {
    // Process stop events handling

    if (!std::holds_alternative<EtwProcStopDataRef>(
            event_context->data->Payload)) {
      return Status::failure("Invalid event payload");
    }

    // Sugar syntax to facilitate the access to the event payload
    const auto& eventPayload =
        std::get<EtwProcStopDataRef>(event_context->data->Payload);

    if (!eventPayload) {
      return Status::failure("Event payload was null");
    }

    newRow["pid"] = BIGINT(eventPayload->ProcessId);
    newRow["ppid"] = BIGINT(eventPayload->ParentProcessId);
    newRow["session_id"] = INTEGER(eventPayload->SessionId);
    newRow["flags"] = INTEGER(eventPayload->Flags);
    newRow["path"] = SQL_TEXT(eventPayload->ImageName);
    newRow["cmdline"] = SQL_TEXT(eventPayload->Cmdline);
    newRow["exit_code"] = INTEGER(eventPayload->ExitCode);
    newRow["username"] = SQL_TEXT(eventPayload->UserName);

    std::vector<Row> rowList;
    rowList.push_back(std::move(newRow));
    addBatch(rowList, eventHeader.UnixTimestamp);
  }

  return Status::success();
}

} // namespace osquery
