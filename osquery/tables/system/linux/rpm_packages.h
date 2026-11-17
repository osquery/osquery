/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <sys/types.h>

namespace osquery {
namespace tables {

/// The kernel overflow IDs, which "nobody" maps to on current distributions.
const uid_t kOverflowUid{65534};
const gid_t kOverflowGid{65534};

/**
 * @brief Drop privileges before reading an RPM database.
 *
 * Drops to "nobody", or to the overflow IDs when that name cannot be resolved.
 * The lookup goes through the `users` table, which only reads /etc/passwd:
 * rpm-ostree systems keep "nobody" in /usr/lib/passwd, and a minimal container
 * may not define it at all.
 *
 * The dropper is a template parameter so tests can replace DropPrivileges.
 *
 * @return true if privileges were dropped, otherwise false.
 */
template <typename Dropper>
bool dropRpmPrivileges(Dropper& dropper) {
  return dropper.dropTo("nobody") || dropper.dropTo(kOverflowUid, kOverflowGid);
}

} // namespace tables
} // namespace osquery
