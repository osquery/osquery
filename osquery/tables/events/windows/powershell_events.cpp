/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem/path.hpp>

#include <osquery/core/flags.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/windows/powershell_events.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace {
const std::time_t kScriptExpirationSchedule{120};
const std::time_t kScriptEventExpiration{60};

const std::string kScriptBlockPrefix{"script_block."};
const std::string kPowershellEventsChannel{
    "microsoft-windows-powershell/operational"};

const int kScriptBlockLoggingEid{4104};

void cleanupLegacyDatabaseEntries() {
  std::vector<std::string> key_list;
  scanDatabaseKeys(kEvents, key_list, kScriptBlockPrefix);

  bool display_error{false};
  for (const auto& key : key_list) {
    auto status = deleteDatabaseValue(kEvents, key);
    if (!status.ok()) {
      display_error = true;
    }
  }

  if (display_error) {
    LOG(ERROR) << "Failed to delete stale script blocks from the database";
  }
}
} // namespace

FLAG(bool,
     enable_powershell_events_subscriber,
     false,
     "Enables Powershell events");
DECLARE_bool(enable_windows_events_publisher);

REGISTER(PowershellEventSubscriber, "event_subscriber", "powershell_events");

struct PowershellEventSubscriber::PrivateData final {
  Context context;
};

PowershellEventSubscriber::PowershellEventSubscriber() : d_(new PrivateData) {}

PowershellEventSubscriber::~PowershellEventSubscriber() {}

Status PowershellEventSubscriber::init() {
  cleanupLegacyDatabaseEntries();

  if (!FLAGS_enable_windows_events_publisher) {
    return Status::failure("Required publisher is disabled by configuration");
  }

  if (!FLAGS_enable_powershell_events_subscriber) {
    return Status::failure("Subscriber disabled by configuration");
  }

  auto subscription = createSubscriptionContext();
  subscription->channel_list.insert(kPowershellEventsChannel);

  subscribe(&PowershellEventSubscriber::Callback, subscription);
  return Status::success();
}

Status PowershellEventSubscriber::generateRow(
    Row& row,
    std::vector<Context::ScriptMessage> script_message_list,
    const std::vector<double>& character_frequency_map) {
  row = {};

  if (script_message_list.empty()) {
    return Status::failure("Empty message list received in Powershell event");
  }

  const auto& first_script_message = script_message_list.front();

  if (first_script_message.expected_message_count !=
      script_message_list.size()) {
    return Status::failure(
        "One or more messages missing from the Powershell event");
  }

  std::string full_script;
  for (const auto& script_message : script_message_list) {
    full_script += script_message.message;
  }

  double cosine_similarity{0.0};
  if (!character_frequency_map.empty()) {
    cosine_similarity = WindowsEventLogPublisher::cosineSimilarity(
        full_script, character_frequency_map);
  }

  row["time"] = INTEGER(first_script_message.osquery_time);
  row["datetime"] = SQL_TEXT(first_script_message.event_time);
  row["script_block_id"] = SQL_TEXT(first_script_message.script_block_id);

  row["script_block_count"] =
      INTEGER(first_script_message.expected_message_count);

  row["script_text"] = SQL_TEXT(std::move(full_script));
  row["script_name"] = SQL_TEXT(first_script_message.script_name);
  row["script_path"] = SQL_TEXT(first_script_message.script_path);
  row["cosine_similarity"] = DOUBLE(cosine_similarity);

  return Status::success();
}

Status PowershellEventSubscriber::parseScriptMessageEvent(
    boost::optional<Context::ScriptMessage>& script_message_opt,
    const boost::property_tree::ptree& event) {
  script_message_opt = {};

  // Get the event timestamp from the Event.System object
  Context::ScriptMessage output;
  output.osquery_time = std::time(nullptr);

  auto time_created_obj_opt =
      event.get_child_optional("Event.System.TimeCreated");

  if (!time_created_obj_opt) {
    return Status::failure(
        "The Event.System.TimeCreated path was not accessible in the XML event "
        "object");
  }

  const auto& time_created_obj = time_created_obj_opt.value();

  output.event_time = time_created_obj.get("<xmlattr>.SystemTime", "");
  if (output.event_time.empty()) {
    return Status::failure(
        "The SystemTime attribute in the TimeCreated object is missing");
  }

  // Parse the rest of the object
  auto event_data_obj_opt = event.get_child_optional("Event.EventData");
  if (!event_data_obj_opt) {
    return Status::failure(
        "The Event.EventData path was not accessible in the XML event object");
  }

  const auto& event_data_obj = event_data_obj_opt.value();

  std::size_t field_count{0U};
  bool malformed_field{false};

  for (const auto& p : event_data_obj) {
    const auto& node = p.second;

    auto field_name = node.get("<xmlattr>.Name", "");
    if (field_name.empty()) {
      malformed_field = true;
      break;
    }

    auto field_string_value = node.data();

    if (field_name == "MessageNumber") {
      auto field_integer_value_exp = tryTo<std::size_t>(field_string_value);
      if (field_integer_value_exp.isError()) {
        malformed_field = true;
        break;
      }

      output.message_number = field_integer_value_exp.take();
      ++field_count;

    } else if (field_name == "MessageTotal") {
      auto field_integer_value_exp = tryTo<std::size_t>(field_string_value);
      if (field_integer_value_exp.isError()) {
        malformed_field = true;
        break;
      }

      output.expected_message_count = field_integer_value_exp.take();
      ++field_count;

    } else if (field_name == "ScriptBlockText") {
      output.message = field_string_value;
      ++field_count;

    } else if (field_name == "ScriptBlockId") {
      output.script_block_id = field_string_value;
      ++field_count;

    } else if (field_name == "Path") {
      output.script_path = field_string_value;
      ++field_count;

      if (!output.script_path.empty()) {
        output.script_name =
            boost::filesystem::path(output.script_path).leaf().string();
      }
    }
  }

  if (malformed_field) {
    return Status::failure(
        "Found a malformed field in a Powershell script event.");
  }

  if (field_count != 5U) {
    return Status::success();
  }

  // This is used to display the prompt, and not really useful as an event
  if (output.message == "prompt" && output.script_path.empty() &&
      output.expected_message_count == 1U) {
    return Status::success();
  }

  script_message_opt = std::move(output);
  return Status::success();
}

Status PowershellEventSubscriber::processEventObject(
    Context& context, const boost::property_tree::ptree& event) {
  // Parse the current event and initialize a new script message object
  boost::optional<Context::ScriptMessage> script_message_opt;

  auto status = parseScriptMessageEvent(script_message_opt, event);
  if (!status.ok()) {
    ++context.invalid_event_count;
    return status;
  }

  if (!script_message_opt) {
    return Status::success();
  }

  const auto& script_message = script_message_opt.value();

  // If this is a single-message event, then bypass state tracking and directly
  // emit a new row
  if (script_message.expected_message_count == 1U) {
    Row row;
    status = generateRow(
        row, {std::move(script_message)}, context.character_frequency_map);

    if (!status.ok()) {
      ++context.invalid_event_count;
      return status;
    }

    context.row_list.push_back(std::move(row));
    return Status::success();
  }

  // Get or create a new script message list object
  auto script_block_id = script_message.script_block_id;
  auto expected_message_count = script_message.expected_message_count;

  auto script_message_list_it = context.script_state_map.find(script_block_id);
  if (script_message_list_it == context.script_state_map.end()) {
    auto insert_status = context.script_state_map.insert({script_block_id, {}});
    script_message_list_it = insert_status.first;
  }

  auto& script_message_list_ref = script_message_list_it->second;
  script_message_list_ref.push_back(std::move(script_message));

  // If we have finished assembling this event, then emit a new row
  if (expected_message_count != script_message_list_ref.size()) {
    return Status::success();
  }

  auto script_message_list = std::move(script_message_list_ref);
  context.script_state_map.erase(script_block_id);

  Row row;
  status = generateRow(
      row, std::move(script_message_list), context.character_frequency_map);

  if (!status.ok()) {
    ++context.invalid_event_count;
    return status;
  }

  context.row_list.push_back(std::move(row));
  return Status::success();
}

Status PowershellEventSubscriber::processEventExpiration(Context& context) {
  auto current_timestamp = std::time(nullptr);

  if (current_timestamp - context.last_event_expiration_time <
      kScriptExpirationSchedule) {
    return Status::success();
  }

  context.last_event_expiration_time = current_timestamp;

  for (auto it = context.script_state_map.begin();
       it != context.script_state_map.end();) {
    const auto& script_message_list = it->second;
    const auto& last_script_message = script_message_list.back();

    if (last_script_message.osquery_time + kScriptEventExpiration <
        current_timestamp) {
      it = context.script_state_map.erase(it);
      ++context.expired_event_count;

    } else {
      ++it;
    }
  }

  return Status::success();
}

Status PowershellEventSubscriber::Callback(const ECRef& event,
                                           const SCRef& subscription) {
  d_->context.character_frequency_map = subscription->character_frequency_map;

  for (const auto& event_object : event->event_objects) {
    auto status = processEventObject(d_->context, event_object);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
    }
  }

  auto row_list = std::move(d_->context.row_list);
  d_->context.row_list = {};

  if (!row_list.empty()) {
    addBatch(row_list);
  }

  if (d_->context.invalid_event_count > 0U) {
    LOG(ERROR) << "Found " << d_->context.invalid_event_count
               << " invalid event objects in powershell_events";

    d_->context.invalid_event_count = 0;
  }

  auto status = processEventExpiration(d_->context);
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
  }

  if (d_->context.expired_event_count > 0U) {
    LOG(ERROR)
        << d_->context.expired_event_count
        << " incomplete script events have been expired in powershell_events";

    d_->context.expired_event_count = 0;
  }

  return Status::success();
}
} // namespace osquery
