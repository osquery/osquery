/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <glog/logging.h>

namespace osquery {

/**
 * @brief Helper logging macro for table-generated verbose log lines.
 *
 * Since logging in tables does not always mean a critical warning or error
 * but more likely a parsing or expected edge-case, we provide a TLOG.
 *
 * The tool user can set within config or via the CLI what level of logging
 * to tolerate. It's the table developer's job to assume consistency in logging.
 */
#define TLOG VLOG(1)

/**
 * @brief Prepend a reference number to the log line.
 *
 * A reference number is an external-search helper for somewhat confusing or
 * seeminly-critical log lines.
 */
#define RLOG(n) "[Ref #" #n "] "

} // namespace osquery
