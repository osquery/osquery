/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/query.h>
#include <osquery/core/tables.h>

#include <string>
#include <vector>

namespace osquery {
namespace tables {

struct AptSource {
  std::string base_uri;
  std::string name;

  // Components of the cache filename.
  std::vector<std::string> cache_file;
};

Status parseAptSourceLine(const std::string& input_line, AptSource& apt_source);

std::string getCacheFilename(const std::vector<std::string>& cache_file);

} // namespace tables
} // namespace osquery
