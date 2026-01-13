/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/linux/bpf/serializers.h>

#include <fcntl.h>

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

namespace osquery {

// ebpfpub removed - parameter list map is now empty
const ParameterListMap kParameterListMap = {};

} // namespace osquery
