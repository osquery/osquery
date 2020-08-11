/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifdef WIN32
#include <intrin.h>
#endif

#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

#define FEATURE(name, reg, bit) std::make_pair(name, std::make_pair(reg, bit))

namespace osquery {
namespace tables {

using RegisterBit = std::pair<std::string, size_t>;
using FeatureDef = std::pair<std::string, RegisterBit>;

std::map<size_t, std::vector<FeatureDef>> kCPUFeatures{
    {1,
     {
         FEATURE("pae", "edx", 6),         FEATURE("msr", "edx", 5),
         FEATURE("sep", "edx", 11),        FEATURE("mtrr", "edx", 12),
         FEATURE("pge", "edx", 13),        FEATURE("mca", "edx", 14),
         FEATURE("pat", "edx", 16),        FEATURE("clfsh", "edx", 19),
         FEATURE("acpi", "edx", 22),       FEATURE("mmz", "edx", 23),
         FEATURE("sse", "edx", 25),        FEATURE("sse2", "edx", 26),
         FEATURE("ss", "edx", 27),         FEATURE("htt", "edx", 28),
         FEATURE("ia64", "edx", 30),

         FEATURE("sse3", "ecx", 0),        FEATURE("vmx", "ecx", 5),
         FEATURE("smx", "ecx", 6),         FEATURE("ssse3", "ecx", 9),
         FEATURE("sdbg", "ecx", 11),       FEATURE("pdcm", "ecx", 15),
         FEATURE("pcid", "ecx", 17),       FEATURE("dca", "ecx", 18),
         FEATURE("sse4.1", "ecx", 19),     FEATURE("sse4.2", "ecx", 20),
         FEATURE("aes", "ecx", 25),        FEATURE("avx", "ecx", 28),
         FEATURE("hypervisor", "ecx", 31),
     }},
    {7,
     {
         FEATURE("sgx", "ebx", 2),        FEATURE("hle", "ebx", 4),
         FEATURE("avx2", "ebx", 5),       FEATURE("smep", "ebx", 7),
         FEATURE("bmi2", "ebx", 8),       FEATURE("erms", "ebx", 9),
         FEATURE("invpcid", "ebx", 10),   FEATURE("rtm", "ebx", 11),
         FEATURE("pqm", "ebx", 12),       FEATURE("mpx", "ebx", 14),
         FEATURE("pqe", "ebx", 15),       FEATURE("avx512f", "ebx", 16),
         FEATURE("avx512dq", "ebx", 17),  FEATURE("rdseed", "ebx", 18),
         FEATURE("adx", "ebx", 19),       FEATURE("smap", "ebx", 20),
         FEATURE("intel_pt", "ebx", 25),  FEATURE("sha", "ebx", 29),

         FEATURE("umip", "ecx", 2),       FEATURE("pku", "ecx", 3),
         FEATURE("ospke", "ecx", 4),      FEATURE("gfni", "ecx", 8),
         FEATURE("vaes", "ecx", 9),       FEATURE("sgx_lc", "ecx", 30),

         FEATURE("spec_ctrl", "edx", 26),
     }},
    {0x80000001,
     {
         FEATURE("lahfsahf", "ecx", 0),
         FEATURE("svm", "ecx", 2),
         FEATURE("3dnowprefetch", "ecx", 8),
         FEATURE("ibs", "ecx", 10),
         FEATURE("skinit", "ecx", 12),
         FEATURE("lwp", "ecx", 15),

         FEATURE("nx", "edx", 20),
         FEATURE("page1gb", "edx", 26),
         FEATURE("lm", "edx", 29),
     }}};

static inline void cpuid(size_t eax, size_t ecx, int regs[4]) {
#if defined(WIN32)
  __cpuidex(
      static_cast<int*>(regs), static_cast<int>(eax), static_cast<int>(ecx));
#else
  asm volatile("cpuid"
               : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
               : "a"(eax), "c"(ecx));
#endif
}

static inline void registerToString(int reg, std::stringstream& stream) {
  for (size_t i = 0; i < 4; i++) {
    stream << ((char*)&reg)[i];
  }
}

static inline bool isBitSet(size_t bit, unsigned int reg) {
  return ((reg & (1 << bit)) != 0);
}

inline Status genStrings(QueryData& results) {
  int regs[4] = {-1};

  cpuid(0, 0, regs);
  if (regs[0] < 1) {
    // The CPUID ASM call is not supported.
    return Status(1, "Failed to run cpuid");
  }

  std::stringstream vendor_string;
  registerToString(regs[1], vendor_string);
  registerToString(regs[3], vendor_string);
  registerToString(regs[2], vendor_string);

  Row r;
  r["feature"] = "vendor";
  r["value"] = vendor_string.str();
  r["output_register"] = "ebx,edx,ecx";
  r["output_bit"] = "0";
  r["input_eax"] = "0";
  results.push_back(r);

  // The CPU canonicalized name can also be accessed via cpuid accesses.
  // Subsequent accesses allow a 32-character CPU name.
  std::stringstream product_name;
  for (size_t i = 0; i < 3; i++) {
    cpuid(0x80000002 + i, 0U, regs);
    registerToString(regs[0], product_name);
    registerToString(regs[1], product_name);
    registerToString(regs[2], product_name);
    registerToString(regs[3], product_name);
  }

  r["feature"] = "product_name";
  r["value"] = product_name.str();
  r["output_register"] = "eax,ebx,ecx,edx";
  r["output_bit"] = "0";
  r["input_eax"] = "0x80000002";
  results.push_back(r);

  // Do the same to grab the optional hypervisor ID.
  cpuid(0x40000000, 0, regs);
  if (regs[0] && 0xFF000000 != 0) {
    std::stringstream hypervisor;
    hypervisor << std::hex << std::setw(8) << std::setfill('0')
               << static_cast<int>(regs[0]);
    hypervisor << std::hex << std::setw(8) << std::setfill('0')
               << static_cast<int>(regs[1]);
    hypervisor << std::hex << std::setw(8) << std::setfill('0')
               << static_cast<int>(regs[2]);

    r["feature"] = "hypervisor_id";
    r["value"] = hypervisor.str();
    r["output_register"] = "ebx,ecx,edx";
    r["output_bit"] = "0";
    r["input_eax"] = "0x40000000";
    results.push_back(r);
  }

  // Finally, check the processor serial number.
  std::stringstream serial;
  cpuid(1, 0, regs);
  serial << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[0]);
  cpuid(3, 0, regs);
  serial << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[0]);
  serial << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[3]);

  r["feature"] = "serial";
  r["value"] = serial.str();
  r["output_register"] = "eax,eax,ecx";
  r["output_bit"] = "0";
  r["input_eax"] = "1,3";
  results.push_back(r);

  return Status::success();
}

inline void genFamily(QueryData& results) {
  int regs[4] = {-1};

  cpuid(1, 0, regs);
  auto family = regs[0] & 0xf00;

  std::stringstream family_string;
  family_string << std::hex << std::setw(4) << std::setfill('0') << family;

  Row r;
  r["feature"] = "family";
  r["value"] = family_string.str();
  r["output_register"] = "eax";
  r["output_bit"] = "0";
  r["input_eax"] = "1";

  results.push_back(r);
}

QueryData genCPUID(QueryContext& context) {
  QueryData results;

  if (!genStrings(results).ok()) {
    return results;
  }

  // Get the CPU meta-data about the model, stepping, family.
  genFamily(results);

  int regs[4] = {-1};
  for (const auto& feature_set : kCPUFeatures) {
    auto eax = feature_set.first;
    cpuid(eax, 0, regs);

    for (const auto& feature : feature_set.second) {
      Row r;

      r["feature"] = feature.first;

      // Get the return register holding the feature bit.
      auto feature_register = 0;
      if (feature.second.first == "edx") {
        feature_register = 3;
      } else if (feature.second.first == "ebx") {
        feature_register = 1;
      } else if (feature.second.first == "ecx") {
        feature_register = 2;
      }

      auto feature_bit = feature.second.second;
      r["value"] = isBitSet(feature_bit, regs[feature_register]) ? "1" : "0";
      r["output_register"] = feature.second.first;
      r["output_bit"] = INTEGER(feature_bit);
      r["input_eax"] = std::to_string(eax);
      results.push_back(r);
    }
  }

  {
    Row r;
    r["output_register"] = "eax,ebx,ecx,edx";
    r["output_bit"] = INTEGER(0);

    cpuid(0x12, 0, regs);
    std::stringstream sgx0;
    sgx0 << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[0]);
    sgx0 << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[1]);
    sgx0 << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[2]);
    sgx0 << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[3]);
    r["feature"] = "sgx0";
    r["value"] = sgx0.str();
    r["input_eax"] = std::to_string(0x12);
    results.push_back(r);

    cpuid(0x12, 1, regs);
    std::stringstream sgx1;
    sgx1 << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[0]);
    sgx1 << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[1]);
    sgx1 << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[2]);
    sgx1 << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<int>(regs[3]);
    r["feature"] = "sgx1";
    r["value"] = sgx1.str();
    r["input_eax"] = std::to_string(0x12) + ",1";
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
