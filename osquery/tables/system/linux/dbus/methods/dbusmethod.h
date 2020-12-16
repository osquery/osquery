/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/dbus/uniquedbusconnection.h>
#include <osquery/tables/system/linux/dbus/uniquedbusmessage.h>

#include <dbus/dbus.h>

namespace osquery {

template <typename MethodHandler, typename... ArgumentList>
class DbusMethod final : public MethodHandler {
 public:
  using Output = typename MethodHandler::Output;
  using MethodHandler::parseReply;

  Status call(Output& output,
              const UniqueDbusConnection& connection,
              const std::string& object_path,
              ArgumentList... args) const {
    output = {};

    UniqueDbusMessage message;
    auto status = UniqueDbusMessage::create(message,
                                            MethodHandler::kDestination,
                                            object_path,
                                            MethodHandler::kInterface,
                                            MethodHandler::kMethod);
    if (!status.ok()) {
      return status;
    }

    processParameterList(message, args...);

    UniqueDbusMessage reply;
    status = sendMessage(connection, reply, message);
    if (!status.ok()) {
      return status;
    }

    return parseReply(output, reply);
  }

  DbusMethod() = default;
  virtual ~DbusMethod() override = default;

  DbusMethod(const DbusMethod&) = delete;
  DbusMethod& operator=(const DbusMethod&) = delete;

 private:
  Status sendMessage(const UniqueDbusConnection& connection,
                     UniqueDbusMessage& reply,
                     const UniqueDbusMessage& message) const {
    reply.release();

    if (!message) {
      return Status::failure("The message object has not been initialized");
    }

    DBusError error DBUS_ERROR_INIT;
    auto reply_ptr = dbus_connection_send_with_reply_and_block(
        connection.get(), message.get(), -1, &error);

    if (dbus_error_is_set(&error)) {
      std::stringstream message;
      message << "Failed to call the dbus method: " << error.message << " ("
              << error.name << ")";

      dbus_error_free(&error);
      return Status::failure(message.str());
    }

    if (reply_ptr == nullptr) {
      return Status::failure("Failed to send the dbus request");
    }

    reply.reset(reply_ptr);
    return Status::success();
  }

  bool processParameter(Status& status,
                        DBusMessageIter& message_it,
                        const std::string& param) const {
    auto string_ptr = param.c_str();
    if (!dbus_message_iter_append_basic(
            &message_it, DBUS_TYPE_STRING, &string_ptr)) {
      status = Status::failure("Failed to append the string parameter");
      return false;
    }

    status = Status::success();
    return true;
  }

  template <class... ParameterList>
  Status processParameterList(UniqueDbusMessage& message,
                              ParameterList const&... parameter_list) const {
    DBusMessageIter message_it{};
    dbus_message_iter_init_append(message.get(), &message_it);

    Status status;
    if (!(processParameter(status, message_it, parameter_list) && ...)) {
      return status;
    }

    return Status::success();
  }
};

template <typename FieldType, int dbus_type_id>
FieldType readDbusMessageField(DBusMessageIter& it, bool increment_iterator) {
  if (dbus_message_iter_get_arg_type(&it) != dbus_type_id) {
    throw Status::failure("Unexpected type encountered");
  }

  FieldType value{};
  dbus_message_iter_get_basic(&it, &value);

  if (increment_iterator) {
    if (!dbus_message_iter_has_next(&it)) {
      throw Status::failure("Unexpected end of message encountered");
    }

    if (!dbus_message_iter_next(&it)) {
      throw Status::failure("Failed to increment the field iterator");
    }
  }

  return value;
}

const auto readDbusMessageStringField{
    readDbusMessageField<const char*, DBUS_TYPE_STRING>};

const auto readDbusMessageObjectPathField{
    readDbusMessageField<const char*, DBUS_TYPE_OBJECT_PATH>};

const auto readDbusMessageUint32Field{
    readDbusMessageField<std::uint32_t, DBUS_TYPE_UINT32>};
} // namespace osquery
