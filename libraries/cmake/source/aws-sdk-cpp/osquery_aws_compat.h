/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#if defined(_WIN32) && defined(_MSC_VER)

#include <cstddef>

namespace stdext {

template <typename OutputIterator>
constexpr OutputIterator checked_array_iterator(OutputIterator output_iterator,
                                                std::size_t) noexcept {
  return output_iterator;
}

} // namespace stdext

#endif // defined(_WIN32) && defined(_MSC_VER)
