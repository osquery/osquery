/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/system/linux/dbus/uniquedbusmessage.h>

namespace osquery {

Status UniqueDbusMessageAllocator::allocate(ResourceType& message,
                                            const std::string& destination,
                                            const std::string& path,
                                            const std::string& iface,
                                            const std::string& method) {
  message = dbus_message_new_method_call(
      destination.c_str(), path.c_str(), iface.c_str(), method.c_str());
  if (message == nullptr) {
    return Status::failure("Failed to create the systemd method call");
  }

  return Status::success();
}

void UniqueDbusMessageAllocator::deallocate(ResourceType& message) {
  if (message == nullptr) {
    return;
  }

  dbus_message_unref(message);
  message = nullptr;
}

} // namespace osquery
