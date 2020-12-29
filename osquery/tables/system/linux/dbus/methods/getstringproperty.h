/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <osquery/tables/system/linux/dbus/methods/dbusmethod.h>
#include <osquery/utils/status/status.h>

#include <dbus/dbus.h>

namespace osquery {

class GetStringPropertyMethodHandler {
 public:
  constexpr static auto kDestination{"org.freedesktop.systemd1"};
  constexpr static auto kInterface{"org.freedesktop.DBus.Properties"};
  constexpr static auto kMethod{"Get"};

  using Output = std::string;
  Status parseReply(Output& output, const UniqueDbusMessage& reply) const;

 protected:
  GetStringPropertyMethodHandler() = default;
  virtual ~GetStringPropertyMethodHandler() = default;
};

using GetStringPropertyMethod = DbusMethod<GetStringPropertyMethodHandler,
                                           const std::string&,
                                           const std::string&>;

} // namespace osquery
