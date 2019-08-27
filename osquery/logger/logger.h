/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#ifdef WIN32
#define GLOG_NO_ABBREVIATED_SEVERITIES
#define GOOGLE_GLOG_DLL_DECL
#endif

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
