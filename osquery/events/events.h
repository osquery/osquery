/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

namespace osquery {

/// Iterate the event publisher registry and create run loops for each using
/// the event factory.
void attachEvents();

/// Return true if a query operates only on event-based tables and should be
/// denylisted.
bool enforceEventsDenylist(const std::string& query);

} // namespace osquery
