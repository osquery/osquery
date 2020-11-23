/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/tables/system/linux/dbus/uniqueresource.h>

#include <dbus/dbus.h>

namespace osquery {

class UniqueDbusMessageAllocator {
 protected:
  using ResourceType = DBusMessage*;

  UniqueDbusMessageAllocator() = default;
  virtual ~UniqueDbusMessageAllocator() = default;

  static Status allocate(ResourceType& message,
                         const std::string& destination,
                         const std::string& path,
                         const std::string& iface,
                         const std::string& method);
  static void deallocate(ResourceType& message);
};

using UniqueDbusMessage = UniqueResource<UniqueDbusMessageAllocator,
                                         const std::string&,
                                         const std::string&,
                                         const std::string&,
                                         const std::string&>;

} // namespace osquery
