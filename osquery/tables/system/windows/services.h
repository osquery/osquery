/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Winsvc.h>

#include <osquery/core.h>
#include <osquery/tables.h>
namespace osquery {
namespace tables {

const auto freePtr = [](auto ptr) { free(ptr); };
const auto closeServiceHandle = [](SC_HANDLE sch) { CloseServiceHandle(sch); };

using svc_descr_t = std::unique_ptr<SERVICE_DESCRIPTION, decltype(freePtr)>;
using svc_handle_t = std::unique_ptr<SC_HANDLE__, decltype(closeServiceHandle)>;
using svc_query_t = std::unique_ptr<QUERY_SERVICE_CONFIG, decltype(freePtr)>;
using enum_svc_status_t =
    std::unique_ptr<ENUM_SERVICE_STATUS_PROCESS[], decltype(freePtr)>;

} // namespace tables
} // namespace osquery
