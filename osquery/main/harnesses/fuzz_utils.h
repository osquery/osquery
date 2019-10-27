/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
