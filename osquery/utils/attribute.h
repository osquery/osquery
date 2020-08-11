/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#if __cplusplus >= 201703L
#define OSQUERY_NODISCARD [[nodiscard]]
#else
#if defined(POSIX)
#define OSQUERY_NODISCARD __attribute__((warn_unused_result))
#elif defined(WIDOWS) && defined(_MSC_VER) && _MSC_VER >= 1700
#define OSQUERY_NODISCARD _Check_return_
#else
#define OSQUERY_NODISCARD
#endif
#endif
