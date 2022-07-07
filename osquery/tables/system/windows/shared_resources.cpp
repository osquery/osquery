/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <unordered_map>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger/logger.h>

namespace osquery::tables {

namespace {

// Documentation:
// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-share
const std::string kWin32ShareQuery{"SELECT * FROM Win32_Share"};

const std::unordered_map<long, std::string> kShareTypeNameMap = {
    {0, "Disk Drive"},
    {1, "Print Queue"},
    {2, "Device"},
    {3, "IPC"},
    {2147483648, "Disk Drive Admin"},
    {2147483649, "Print Queue Admin"},
    {2147483650, "Device Admin"},
    {2147483651, "IPC Admin"}};

const std::string& getShareTypeName(const long& share_type) {
  static const std::string kInvalidShareTypeName;

  auto it = kShareTypeNameMap.find(share_type);
  if (it == kShareTypeNameMap.end()) {
    return kInvalidShareTypeName;
  }

  return it->second;
}

} // namespace

QueryData genShares(QueryContext& context) {
  auto exp_request = WmiRequest::CreateWmiRequest(kWin32ShareQuery);
  if (exp_request.isError()) {
    const auto& error = exp_request.getError();

    LOG(ERROR) << "The following WMI query could not be constructed: "
               << kWin32ShareQuery << ". " << error.getMessage();

    return {};
  }

  auto request = exp_request.take();
  if (!request.getStatus().ok()) {
    LOG(ERROR) << "The following WMI query could not be executed correctly: "
               << kWin32ShareQuery;
    return {};
  }

  const auto& wmi_item_list = request.results();
  if (wmi_item_list.empty()) {
    return {};
  }

  QueryData row_list;

  for (const auto& wmi_item : wmi_item_list) {
    Row row;
    wmi_item.GetString("Description", row["description"]);
    wmi_item.GetString("InstallDate", row["install_date"]);
    wmi_item.GetString("Status", row["status"]);
    wmi_item.GetString("Name", row["name"]);
    wmi_item.GetString("Path", row["path"]);

    bool allow_maximum{};
    auto status = wmi_item.GetBool("AllowMaximum", allow_maximum);
    row["allow_maximum"] = INTEGER(status.ok() ? allow_maximum : -1);

    long raw_maximum_allowed_value{};
    status = wmi_item.GetLong("MaximumAllowed", raw_maximum_allowed_value);

    if (status.ok()) {
      auto maximum_allowed =
          static_cast<std::uint32_t>(raw_maximum_allowed_value);
      row["maximum_allowed"] = BIGINT(maximum_allowed);
    } else {
      row["maximum_allowed"] = BIGINT(-1);
    }

    long type{};
    status = wmi_item.GetLong("Type", type);
    row["type"] = BIGINT(status.ok() ? static_cast<std::uint32_t>(type) : 0);
    row["type_name"] = SQL_TEXT(getShareTypeName(type));

    row_list.push_back(std::move(row));
    row.clear();
  }

  return row_list;
}

} // namespace osquery::tables
