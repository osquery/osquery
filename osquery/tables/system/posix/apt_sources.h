/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/query.h>
#include <osquery/tables.h>

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
