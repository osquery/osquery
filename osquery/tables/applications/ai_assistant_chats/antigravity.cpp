/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/tables/applications/ai_assistant_chats/antigravity.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kAntigravityApplication{"antigravity"};

namespace {

/**
 * Antigravity keeps a database per conversation under the user's Gemini
 * directory. Releases before 2.x used the first of these names.
 */
const std::vector<std::string> kAntigravityDirectories{"antigravity",
                                                       "antigravity-ide"};

/**
 * The steps of a conversation, oldest first. Their payloads are protobuf,
 * which carries NUL bytes that would cut a text value short, so they come
 * back hex encoded and are decoded here instead.
 */
const std::string kAntigravityStepQuery{
    "SELECT hex(step_payload) AS payload FROM steps ORDER BY idx"};

/**
 * The step kinds that carry something a person said, from the language
 * server's CortexStepType. Every other kind is the agent working.
 */
const std::uint64_t kAntigravityUserStep{14}; // ..._TYPE_USER_INPUT
const std::uint64_t kAntigravityAssistantStep{15}; // ..._TYPE_PLANNER_RESPONSE

/// Field numbers within Step and the messages it nests, see the header.
const std::uint32_t kAntigravityStepKindField{1}; // Step.type
const std::uint32_t kAntigravityMetadataField{5}; // Step.metadata
const std::uint32_t kAntigravityCreatedField{1}; // ...Metadata.created_at
const std::uint32_t kAntigravitySecondsField{1}; // Timestamp.seconds
const std::uint32_t kAntigravityUserBodyField{19}; // Step.user_input
const std::uint32_t kAntigravityUserTextField{2}; // ...UserInput.user_response
const std::uint32_t kAntigravityAssistantBodyField{20}; // Step.planner_response
const std::uint32_t kAntigravityAssistantTextField{
    1}; // ...PlannerResponse.response

/// One field of a protobuf message, as it appears on the wire.
struct ProtobufField final {
  std::uint32_t number{0};
  std::uint8_t wire_type{0};

  /// Set for the numeric wire type, empty otherwise.
  std::uint64_t value{0};

  /// Set for the length delimited wire type, which covers both strings
  /// and nested messages, empty otherwise.
  std::string_view bytes;
};

/**
 * @brief Decodes a protobuf base-128 varint from the input buffer.
 *
 * Advances the buffer past the encoded value when decoding succeeds.
 *
 * @param buffer Input buffer; consumed bytes are removed.
 * @param value Receives the decoded integer.
 * @return `true` if a complete 64-bit varint was decoded, `false` otherwise.
 */
bool readVarint(std::string_view& buffer, std::uint64_t& value) {
  value = 0;

  for (std::size_t shift = 0; shift < 64; shift += 7) {
    if (buffer.empty()) {
      return false;
    }

    auto byte = static_cast<std::uint8_t>(buffer.front());
    buffer.remove_prefix(1);
    value |= static_cast<std::uint64_t>(byte & 0x7f) << shift;

    if ((byte & 0x80) == 0) {
      return true;
    }
  }

  return false;
}

/**
 * @brief Parses the next field from a protobuf message.
 *
 * Advances `message` past the parsed field and stores its number, wire type,
 * and applicable value in `field`. Fixed-width fields are skipped without
 * storing their values.
 *
 * @param message Protobuf message data remaining to parse.
 * @param field Output field populated with the parsed field information.
 * @return true if a complete supported field was parsed, false if the message
 *         is exhausted or malformed.
 */
bool nextProtobufField(std::string_view& message, ProtobufField& field) {
  std::uint64_t key = 0;
  if (!readVarint(message, key)) {
    return false;
  }

  field = {};
  field.number = static_cast<std::uint32_t>(key >> 3);
  field.wire_type = static_cast<std::uint8_t>(key & 0x07);

  switch (field.wire_type) {
  case 0: // A number stored as a varint.
    return readVarint(message, field.value);

  case 1: // A fixed width 64 bit number, skipped over.
  case 5: // A fixed width 32 bit number, skipped over.
  {
    std::size_t width = field.wire_type == 1 ? 8 : 4;
    if (message.size() < width) {
      return false;
    }
    message.remove_prefix(width);
    return true;
  }

  case 2: // A string or a nested message.
  {
    std::uint64_t length = 0;
    if (!readVarint(message, length) || length > message.size()) {
      return false;
    }
    field.bytes = message.substr(0, length);
    message.remove_prefix(length);
    return true;
  }

  default:
    // The group wire types were removed from protobuf long ago, and
    // anything else means this is not the message it was taken for.
    return false;
  }
}

/**
 * @brief Finds the first length-delimited protobuf field with the specified number.
 *
 * @param message Serialized protobuf message to search.
 * @param number Field number to find.
 * @param value Receives the field's byte contents when found.
 * @return `true` if a matching field is found, `false` otherwise.
 */
bool protobufBytes(std::string_view message,
                   std::uint32_t number,
                   std::string_view& value) {
  ProtobufField field;
  while (nextProtobufField(message, field)) {
    if (field.number == number && field.wire_type == 2) {
      value = field.bytes;
      return true;
    }
  }

  return false;
}

/**
 * @brief Finds the first varint field with the specified field number.
 *
 * @param message Protobuf-encoded message to search.
 * @param number Field number to find.
 * @param value Receives the field's decoded value when found.
 * @return `true` if a matching varint field is found, `false` otherwise.
 */
bool protobufVarint(std::string_view message,
                    std::uint32_t number,
                    std::uint64_t& value) {
  ProtobufField field;
  while (nextProtobufField(message, field)) {
    if (field.number == number && field.wire_type == 0) {
      value = field.value;
      return true;
    }
  }

  return false;
}

} /**
 * @brief Decodes an even-length hexadecimal string into binary bytes.
 *
 * @param hex Hexadecimal input containing only hexadecimal digits.
 * @param bytes Output buffer populated with the decoded bytes and cleared on failure.
 * @return true if the input is valid and decoded successfully, false otherwise.
 */

bool decodeHexBlob(const std::string& hex, std::string& bytes) {
  // Deliberately stricter than a general string to number conversion,
  // which would accept the sign, whitespace and prefixes that a hex blob
  // never contains, and quietly turn them into bytes.
  auto digit = [](char character) -> int {
    if (character >= '0' && character <= '9') {
      return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
      return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
      return character - 'A' + 10;
    }
    return -1;
  };

  bytes.clear();
  if (hex.size() % 2 != 0) {
    return false;
  }

  bytes.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    auto high = digit(hex[i]);
    auto low = digit(hex[i + 1]);
    if (high < 0 || low < 0) {
      bytes.clear();
      return false;
    }

    bytes.push_back(static_cast<char>((high << 4) | low));
  }

  return true;
}
/**
 * @brief Extracts a user or assistant message from an Antigravity conversation step.
 *
 * @param payload Serialized conversation-step data.
 * @param session_id Conversation session identifier.
 * @param path Path to the source conversation database.
 * @param results Collection to which a parsed message is appended.
 */
void parseAntigravityStep(const std::string& payload,
                          const std::string& session_id,
                          const std::string& path,
                          std::vector<AIAssistantChat>& results) {
  std::string_view step(payload);

  std::uint64_t kind = 0;
  if (!protobufVarint(step, kAntigravityStepKindField, kind)) {
    return;
  }

  std::uint32_t body_field = 0;
  std::uint32_t text_field = 0;
  std::string role;

  if (kind == kAntigravityUserStep) {
    role = kUserRole;
    body_field = kAntigravityUserBodyField;
    text_field = kAntigravityUserTextField;
  } else if (kind == kAntigravityAssistantStep) {
    role = kAssistantRole;
    body_field = kAntigravityAssistantBodyField;
    text_field = kAntigravityAssistantTextField;
  } else {
    // Every other kind of step is the agent working rather than talking.
    return;
  }

  std::string_view body;
  std::string_view text;
  if (!protobufBytes(step, body_field, body) ||
      !protobufBytes(body, text_field, text) || text.empty()) {
    // A step of the right kind with nothing written on it is a turn that
    // said nothing, such as a prompt that only attached a file.
    return;
  }

  AIAssistantChat chat;
  chat.application = kAntigravityApplication;
  chat.session_id = session_id;
  chat.role = std::move(role);
  chat.message = std::string(text);
  chat.path = path;

  std::string_view common;
  std::string_view created;
  std::uint64_t seconds = 0;
  if (protobufBytes(step, kAntigravityMetadataField, common) &&
      protobufBytes(common, kAntigravityCreatedField, created) &&
      protobufVarint(created, kAntigravitySecondsField, seconds)) {
    chat.timestamp = static_cast<std::int64_t>(seconds);
  }

  results.push_back(std::move(chat));
}
/**
 * @brief Collects chat messages from Antigravity conversation databases.
 *
 * @param home User home directory containing the Gemini conversation directories.
 * @param results Output collection to which extracted chats are appended.
 */
void collectAntigravityChats(const fs::path& home,
                             std::vector<AIAssistantChat>& results) {
  std::vector<std::string> databases;
  for (const auto& directory : kAntigravityDirectories) {
    resolveFilePattern(home / ".gemini" / directory / "conversations" / "%.db",
                       databases,
                       GLOB_FILES);
  }

  for (const auto& path : databases) {
    TableRows rows;
    auto status = genTableRowsForSqliteTable(path, kAntigravityStepQuery, rows);
    if (!status.ok()) {
      VLOG(1) << "Could not read Antigravity conversation " << path << ": "
              << status.getMessage();
      continue;
    }

    // Every conversation is named after the trajectory it holds.
    auto session_id = fs::path(path).stem().string();

    for (const auto& table_row : rows) {
      auto row = static_cast<Row>(*table_row);

      auto payload = row.find("payload");
      if (payload == row.end()) {
        continue;
      }

      std::string step;
      if (!decodeHexBlob(payload->second, step)) {
        VLOG(1) << "Skipping unreadable Antigravity step in " << path;
        continue;
      }

      parseAntigravityStep(step, session_id, path, results);
    }
  }
}

} // namespace tables
} // namespace osquery
