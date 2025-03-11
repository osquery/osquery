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
#include <osquery/tables/events/windows/dns_lookup_events.h>

namespace osquery {

REGISTER_ETW_SUBSCRIBER(EtwDNSEventSubscriber, "dns_lookup_events");
DECLARE_bool(enable_dns_lookup_events);

Status EtwDNSEventSubscriber::init() {
  if (!FLAGS_enable_dns_lookup_events) {
    return Status::failure("subscriber disabled via configuration.");
  }
  auto subscription_context = createSubscriptionContext();
  subscribe(&EtwDNSEventSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status EtwDNSEventSubscriber::eventCallback(const ECRef& event_context,
                                            const SCRef& event_subscription) {
  if ((!event_context) || (!event_context->data)) {
    return Status::failure("Invalid event context");
  }

  // New event row to capture the incoming ETW event data
  Row newRow;

  // Sugar syntax to facilitate the access to the event header
  const auto& eventHeader = event_context->data->Header;

  // Common fields
  newRow["datetime"] = BIGINT(eventHeader.UnixTimestamp);
  newRow["time_windows"] = BIGINT(eventHeader.WinTimestamp);

  if (!std::holds_alternative<EtwDnsRequestDataRef>(
          event_context->data->Payload)) {
    return Status::failure("Invalid event payload");
  }

  // Sugar syntax to facilitate the access to the event payload
  const auto& eventPayload =
      std::get<EtwDnsRequestDataRef>(event_context->data->Payload);

  if (!eventPayload) {
    return Status::failure("Event payload was null");
  }

  newRow["pid"] = BIGINT(eventPayload->ProcessId);
  newRow["path"] = SQL_TEXT(eventPayload->ProcessImagePath);
  newRow["username"] = SQL_TEXT(eventPayload->UserName);
  newRow["name"] = SQL_TEXT(eventPayload->QueryName);
  newRow["type"] = SQL_TEXT(eventPayload->QueryTypeString);
  newRow["type_id"] = INTEGER(eventPayload->QueryType);
  newRow["status"] = INTEGER(eventPayload->QueryStatus);
  newRow["response"] = SQL_TEXT(eventPayload->QueryResults);

  std::vector<Row> rowList;
  rowList.push_back(std::move(newRow));
  addBatch(rowList, eventHeader.UnixTimestamp);

  return Status::success();
}

} // namespace osquery
