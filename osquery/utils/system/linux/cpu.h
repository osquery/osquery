/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/expected/expected.h>

#include <bitset>
#include <string>

namespace osquery {
namespace cpu {

/**
 * CPU topology info exported via sysfs in linux
 * @see Documentation/cputopology.txt in linux kernel code
 */

enum class Error {
  IOError = 1,
  IncorrectRange = 2,
};

constexpr std::size_t kMaskSize = 128; // see NR_CPUS from linux/cpumask.h
using Mask = std::bitset<kMaskSize>;

/**
 * @brief Decode string representation of CPU mask to Mask (aka std::bitset)
 */
Expected<Mask, Error> decodeMaskFromString(const std::string& encoded_str);

/**
 * @brief Return the CPUs that are not online because they have been HOTPLUGGED
 * off or exceed the limit of CPUs allowed by the kernel configuration
 * (kernel_max above).
 */
Expected<std::string, Error> getOfflineRaw();
Expected<Mask, Error> getOffline();

/**
 * @brief Return the CPUs that are online and being scheduled
 */
Expected<std::string, Error> getOnlineRaw();
Expected<Mask, Error> getOnline();

/**
 * @brief Return the CPUs that have been allocated resources and can be brought
 * online if they are present.
 */
Expected<std::string, Error> getPossibleRaw();
Expected<Mask, Error> getPossible();

/**
 * @brief Return the CPUs that have been identified as being present in the
 * system
 */
Expected<std::string, Error> getPresentRaw();
Expected<Mask, Error> getPresent();

} // namespace cpu
} // namespace osquery
