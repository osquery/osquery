/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstdint>
#include <string>

namespace osquery {
namespace tables {

/**
 * @brief Tells whether libmagic can load a magic_load() list entry without
 * parsing a compiled database of another format version as rule source.
 *
 * libmagic maps "<path without .mgc>.mgc" as a compiled database. If that is
 * missing, is not a compiled database or has another format version, it
 * parses path itself as rule source (a rules file or a Magdir directory),
 * printing a warning to stderr for every line it cannot parse. A compiled
 * database of another version yields hundreds of them on every load.
 *
 * @param path an entry of a magic_load() list
 * @param supported_version the compiled database format version the loading
 * libmagic accepts
 *
 * @return true if path is a compiled database of supported_version, has one
 * next to it, or is rule source; false if it does not exist or libmagic would
 * parse a compiled database as rule source
 */
bool isLoadableMagicDatabase(const std::string& path,
                             std::uint32_t supported_version);

} // namespace tables
} // namespace osquery
