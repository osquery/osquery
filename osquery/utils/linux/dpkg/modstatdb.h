/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

// Acknowledge that the API is volatile; required for the
// headers to work correctly
#define LIBDPKG_VOLATILE_API

extern "C" {
#include <dpkg/dpkg-db.h>
}

namespace osquery {

class ModstatDB final {
 public:
  static ModstatDB open() {
    return ModstatDB();
  }

  ~ModstatDB() {
    modstatdb_shutdown();
  }

  ModstatDB(const ModstatDB&) = delete;
  ModstatDB& operator=(const ModstatDB&) = delete;

 private:
  ModstatDB() {
    auto modstatdb_options = static_cast<enum modstatdb_rw>(
        msdbrw_readonly | msdbrw_available_readonly);

    modstatdb_open(modstatdb_options);
  }
};

} // namespace osquery
