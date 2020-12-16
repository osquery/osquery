/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/system/linux/dbus/methods/getstringproperty.h>

namespace osquery {

Status GetStringPropertyMethodHandler::parseReply(
    Output& output, const UniqueDbusMessage& reply) const {
  output = {};

  DBusMessageIter message_it{};
  if (!dbus_message_iter_init(reply.get(), &message_it)) {
    return Status::failure("Failed to initialize the field iterator");
  }

  if (dbus_message_iter_get_arg_type(&message_it) != DBUS_TYPE_VARIANT) {
    return Status::failure(
        "The method reply is encoded in an unexpected format");
  }

  DBusMessageIter variant_it{};
  dbus_message_iter_recurse(&message_it, &variant_it);

  try {
    output = readDbusMessageStringField(variant_it, false);
    return Status::success();

  } catch (const Status& status) {
    return status;
  }
}

} // namespace osquery
