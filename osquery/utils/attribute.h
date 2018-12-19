/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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
