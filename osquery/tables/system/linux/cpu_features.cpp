/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

#if defined(__aarch64__)
#include <array>
#include <cstddef>

#include <elf.h>
#include <sys/auxv.h>
#endif

namespace osquery {
namespace tables {

#if defined(__aarch64__)
namespace {

// Security-relevant arm64 HWCAP bits: hardware exploit mitigations, plus the
// crypto and SIMD extensions that gate JIT/library intrinsics. Bit positions
// are the stable arm64 kernel ELF-HWCAP ABI (the kernel's
// Documentation/arch/arm64/elf_hwcaps.rst), named here rather than pulled from
// <asm/hwcap.h> so the build does not depend on the sysroot header's age.
struct Feature {
  const char* name;
  unsigned shift;
};

constexpr std::array<Feature, 16> kHwcap = {{
    {"asimd", 1},
    {"aes", 3},
    {"pmull", 4},
    {"sha1", 5},
    {"sha2", 6},
    {"sha3", 17},
    {"sm3", 18},
    {"sm4", 19},
    {"asimddp", 20},
    {"sha512", 21},
    {"sve", 22},
    {"dit", 24},
    {"ssbs", 28},
    {"sb", 29},
    {"paca", 30},
    {"pacg", 31},
}};

constexpr std::array<Feature, 7> kHwcap2 = {{
    {"sve2", 1},
    {"i8mm", 13},
    {"bf16", 14},
    {"rng", 16},
    {"bti", 17},
    {"mte", 18},
    {"mte3", 22},
}};

template <std::size_t N>
void emit(QueryData& results,
          const std::array<Feature, N>& features,
          unsigned long caps) {
  for (const auto& f : features) {
    Row r;
    r["feature"] = f.name;
    r["value"] = INTEGER((caps >> f.shift) & 1UL ? 1 : 0);
    results.push_back(r);
  }
}

} // namespace

QueryData genCpuFeatures(QueryContext& context) {
  QueryData results;
  emit(results, kHwcap, getauxval(AT_HWCAP));
  emit(results, kHwcap2, getauxval(AT_HWCAP2));
  return results;
}

#else

// The HWCAP feature set is arm64-specific; on other Linux architectures the
// table exists for schema parity but reports no rows.
QueryData genCpuFeatures(QueryContext& context) {
  return {};
}

#endif

} // namespace tables
} // namespace osquery
