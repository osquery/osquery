/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/system/linux/dbus/methods/listunitsmethodhandler.h>

namespace osquery {

namespace {

// Make sure we have an upper limit so we don't risk infinite loops
const std::size_t kMaxSystemdUnitCount{1000U};

} // namespace

Status ListUnitsMethodHandler::parseReply(
    Output& output, const UniqueDbusMessage& reply) const {
  output = {};

  DBusMessageIter message_it{};
  if (!dbus_message_iter_init(reply.get(), &message_it)) {
    return Status::failure("Failed to initialize the field iterator");
  }

  if (dbus_message_iter_get_arg_type(&message_it) != DBUS_TYPE_ARRAY) {
    return Status::failure(
        "The method reply is encoded in an unexpected format");
  }

  DBusMessageIter array_it{};
  dbus_message_iter_recurse(&message_it, &array_it);

  for (std::size_t i{0U}; i < kMaxSystemdUnitCount; ++i) {
    Unit unit = {};
    auto status = readUnitInformation(unit, array_it);
    if (!status.ok()) {
      return status;
    }

    output.push_back(std::move(unit));
    if (!dbus_message_iter_has_next(&array_it)) {
      break;
    }

    dbus_message_iter_next(&array_it);
  }

  return Status::success();
}

Status ListUnitsMethodHandler::readUnitInformation(Unit& unit,
                                                   DBusMessageIter& it) const {
  unit = {};

  if (dbus_message_iter_get_arg_type(&it) != DBUS_TYPE_STRUCT) {
    return Status::failure("Reply is in an unexpected format");
  }

  DBusMessageIter field_it{};
  dbus_message_iter_recurse(&it, &field_it);

  try {
    unit.id = readDbusMessageStringField(field_it, true);
    unit.description = readDbusMessageStringField(field_it, true);
    unit.load_state = readDbusMessageStringField(field_it, true);
    unit.active_state = readDbusMessageStringField(field_it, true);
    unit.sub_state = readDbusMessageStringField(field_it, true);
    unit.following = readDbusMessageStringField(field_it, true);
    unit.path = readDbusMessageObjectPathField(field_it, true);
    unit.job_id = readDbusMessageUint32Field(field_it, true);
    unit.job_type = readDbusMessageStringField(field_it, true);
    unit.job_path = readDbusMessageObjectPathField(field_it, false);

  } catch (const Status& status) {
    return status;
  }

  return Status::success();
}

} // namespace osquery
