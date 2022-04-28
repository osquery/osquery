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
#include <dpkg/pkg-array.h>
#include <dpkg/pkg-show.h>
}

namespace osquery {

class PkgArray final {
 public:
  static PkgArray create() {
    return PkgArray();
  }

  ~PkgArray() {
    pkg_array_destroy(&array);
  }

  struct pkg_array& get() {
    return array;
  }

  PkgArray(const PkgArray&) = delete;
  PkgArray& operator=(const ModstatDB&) = delete;

 private:
  struct pkg_array array {};

  PkgArray() {
    pkg_array_init_from_hash(&array);
    pkg_array_sort(&array, pkg_sorter_by_nonambig_name_arch);
  }
};

} // namespace osquery
