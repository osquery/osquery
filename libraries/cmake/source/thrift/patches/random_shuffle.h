/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <random>

namespace std {

template <class RandomIt>
void random_shuffle(RandomIt first, RandomIt last) {
  std::random_device rng;
  std::mt19937 urng(rng());
  std::shuffle(first, last, urng);
}
} // namespace std
