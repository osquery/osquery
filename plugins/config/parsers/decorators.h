/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <functional>

#include <osquery/config/config.h>
#include <osquery/database/database.h>

namespace osquery {

/// Enforce specific types of decoration.
enum DecorationPoint {
  DECORATE_LOAD,
  DECORATE_ALWAYS,
  DECORATE_INTERVAL,
};

/// Define a map of decoration points to their expected configuration key.
extern const std::map<DecorationPoint, std::string> kDecorationPointKeys;

/**
 * @brief Iterate the discovered decorators for a given point type.
 *
 * The configuration maintains various sources, each may contain a set of
 * decorators. The source tracking is abstracted for the decorator iterator.
 *
 * @param point request execution of decorators for this given point.
 * @param time an optional time for points using intervals.
 * @param source restrict run to a specific config source.
 */
void runDecorators(DecorationPoint point,
                   uint64_t time = 0,
                   const std::string& source = "");

/**
 * @brief Access the internal storage of the Decorator parser.
 *
 * The decoration set is a map of column name to value. It contains the opaque
 * set of decoration point results.
 *
 * Decorations are applied to log items before they are sent to the downstream
 * logging APIs: logString, logSnapshot, etc.
 *
 * @param results the output parameter to write decorations.
 */
void getDecorations(std::map<std::string, std::string>& results);

/// Clear decorations for a source when it updates.
void clearDecorations(const std::string& source);
}
