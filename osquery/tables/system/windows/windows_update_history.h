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
#include <vector>

#include <windows.h>
#include <wuapi.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

enum class WindowsUpdateHistoryError {
  UpdateSearcherError,
  CountError,
  QueryError,
  SizeError,
  EntryError,
  ClientApplicationIDError,
  DateError,
  DescriptionError,
  HResultError,
  OperationError,
  ResultCodeError,
  ServerSelectionError,
  ServiceIDError,
  SupportURLError,
  TitleError,
  IdentityError,
  UpdateIDError,
  UpdateRevisionError,
};

struct WindowsUpdateHistoryEntry {
  std::string clientAppID;
  LONGLONG date;
  std::string description;
  LONG hresult;
  UpdateOperation updateOp;
  OperationResultCode resultCode;
  ServerSelection serverSelection;
  std::string serviceID;
  std::string supportUrl;
  std::string title;
  std::string updateID;
  LONG updateRevision;
};

using WindowsUpdateHistory = std::vector<WindowsUpdateHistoryEntry>;

QueryData renderWindowsUpdateHistory(const WindowsUpdateHistory& history);

} // namespace tables
} // namespace osquery