/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <Objbase.h>
#include <osquery/utils/system/system.h>

#include <osquery/core/system.h>

namespace osquery {

void platformSetup() {
  // Initialize the COM libraries utilized by Windows WMI calls.
  auto ret = ::CoInitializeEx(0, COINIT_MULTITHREADED);
  if (ret != S_OK) {
    ::CoUninitialize();
  }
}

void platformTeardown() {
  // Before we shutdown, we must insure to free the COM libs in windows
  ::CoUninitialize();
}

void alarm(int /* noop */) {
  /* This function is a noop. */
}
} // namespace osquery
