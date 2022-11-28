/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/versioning/semantic.h>

#include <boost/io/quoted.hpp>

namespace osquery {

using boost::io::quoted;

Expected<SemanticVersion, ConversionError> SemanticVersion::tryFromString(
    const std::string& str) {
  auto version = SemanticVersion{};
  auto const major_number_pos = str.find(SemanticVersion::separator);
  {
    if (major_number_pos == std::string::npos) {
      return createError(ConversionError::InvalidArgument)
             << "invalid format: expected 2 separators, found 0 "
             << quoted(str);
    }
    auto major_exp = tryTo<unsigned>(str.substr(0, major_number_pos));
    if (major_exp.isError()) {
      return createError(ConversionError::InvalidArgument,
                         major_exp.takeError())
             << "Invalid major version number, expected unsigned integer, "
                "found "
             << quoted(str);
    }
    version.major = major_exp.take();
  }
  auto const minor_number_pos =
      str.find(SemanticVersion::separator, major_number_pos + 1);
  {
    if (minor_number_pos == std::string::npos) {
      return createError(ConversionError::InvalidArgument)
             << " there are must be 2 separators, found 1 " << quoted(str);
    }
    auto minor_exp = tryTo<unsigned>(
        str.substr(major_number_pos + 1, minor_number_pos - major_number_pos));
    if (minor_exp.isError()) {
      return createError(ConversionError::InvalidArgument,
                         minor_exp.takeError())
             << "Invalid minor version number, expected unsigned integer, "
                "found: "
             << quoted(str);
    }
    version.minor = minor_exp.take();
  }
  {
    auto const patch_number_pos =
        str.find_first_not_of("0123456789", minor_number_pos + 1);
    auto patches_exp = tryTo<unsigned>(
        str.substr(minor_number_pos + 1, patch_number_pos - minor_number_pos));
    if (patches_exp.isError()) {
      return createError(ConversionError::InvalidArgument)
             << "Invalid patches number, expected unsigned integer, found: "
             << quoted(str);
    }
    version.patches = patches_exp.take();
  }
  return version;
}

} // namespace osquery
