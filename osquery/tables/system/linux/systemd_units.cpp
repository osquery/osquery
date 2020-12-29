/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/tables/system/linux/dbus/methods/getstringproperty.h>
#include <osquery/tables/system/linux/dbus/methods/listunitsmethodhandler.h>

namespace osquery {

namespace tables {

namespace {
struct PropertyQueryDesc final {
  std::string property_name;
  std::string column_name;
  std::string interface;
};

const std::vector<PropertyQueryDesc> kStringPropertyQueryList = {
    {"FragmentPath", "fragment_path", "org.freedesktop.systemd1.Unit"},
    {"SourcePath", "source_path", "org.freedesktop.systemd1.Unit"},
    {"User", "user", "org.freedesktop.systemd1.Service"},
};
} // namespace

TableRows genSystemdUnits(QueryContext& context) {
  UniqueDbusConnection connection;
  auto status = UniqueDbusConnection::create(connection, true);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to generate the systemd unit list: "
               << status.getMessage();
    return {};
  }

  ListUnitsMethod::Output unit_list;
  ListUnitsMethod list_units_method;
  status = list_units_method.call(
      unit_list, connection, "/org/freedesktop/systemd1");

  if (!status.ok()) {
    LOG(ERROR) << "Failed to generate the systemd unit list: "
               << status.getMessage();
    return {};
  }

  TableRows results;

  for (const auto& unit : unit_list) {
    auto row = make_table_row();

    row["id"] = TEXT(unit.id);
    row["description"] = TEXT(unit.description);
    row["load_state"] = TEXT(unit.load_state);
    row["active_state"] = TEXT(unit.active_state);
    row["sub_state"] = TEXT(unit.sub_state);
    row["following"] = TEXT(unit.following);
    row["object_path"] = TEXT(unit.path);
    row["job_id"] = BIGINT(unit.job_id);
    row["job_type"] = TEXT(unit.job_type);
    row["job_path"] = TEXT(unit.job_path);

    for (const auto& query : kStringPropertyQueryList) {
      std::string property_value;
      GetStringPropertyMethod get_string_property_method;
      status = get_string_property_method.call(property_value,
                                               connection,
                                               unit.path,
                                               query.interface,
                                               query.property_name);

      if (!status.ok() && query.property_name != "User") {
        LOG(ERROR) << "Failed to query the property " << query.property_name
                   << " on the following systemd unit: " << unit.path;
      }

      row[query.column_name] = TEXT(property_value);
    }

    results.push_back(std::move(row));
  }

  return results;
}

} // namespace tables

} // namespace osquery
