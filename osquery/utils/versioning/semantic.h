/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/expected/expected.h>

#include <string>

namespace osquery {

class SemanticVersion {
 public:
  unsigned major = 0;
  unsigned minor = 0;
  unsigned patches = 0;

 public:
  static constexpr auto separator = '.';

 public:
  static Expected<SemanticVersion, ConversionError> tryFromString(
      const std::string& str);
};

template <typename ToType>
inline typename std::enable_if<std::is_same<ToType, SemanticVersion>::value,
                               Expected<ToType, ConversionError>>::type
tryTo(const std::string& str) {
  return SemanticVersion::tryFromString(str);
}

} // namespace osquery
