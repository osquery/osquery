/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

namespace osquery {
#ifdef OSQUERY_LINUX
/* Attempts to release retained memory if the memory usage
   of the current process goes above a certain threshold. */
void releaseRetainedMemory();
#endif
} // namespace osquery
