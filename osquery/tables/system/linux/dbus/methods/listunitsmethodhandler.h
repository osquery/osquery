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

class ListUnitsMethodHandler {
 public:
  constexpr static auto kDestination{"org.freedesktop.systemd1"};
  constexpr static auto kInterface{"org.freedesktop.systemd1.Manager"};
  constexpr static auto kMethod{"ListUnits"};

  struct Unit final {
    std::string id;
    std::string description;
    std::string load_state;
    std::string active_state;
    std::string sub_state;
    std::string following;
    std::string path;
    std::uint32_t job_id{0U};
    std::string job_type;
    std::string job_path;
  };

  using Output = std::vector<Unit>;
  Status parseReply(Output& output, const UniqueDbusMessage& reply) const;

 protected:
  ListUnitsMethodHandler() = default;
  virtual ~ListUnitsMethodHandler() = default;

  Status readUnitInformation(Unit& unit, DBusMessageIter& it) const;
};

using ListUnitsMethod = DbusMethod<ListUnitsMethodHandler>;

} // namespace osquery
