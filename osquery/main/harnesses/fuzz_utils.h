/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

namespace osquery {

/**
 * Generic initialize function that 'disables' core features.
 *
 * The goal of this logic is to reduce statefulness.
 * Call this within LLVMFuzzerInitialize.
 */
int osqueryFuzzerInitialize(int* argc, char*** argv);

} // namespace osquery
