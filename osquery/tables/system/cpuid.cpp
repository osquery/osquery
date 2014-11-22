// Copyright 2004-present Facebook. All Rights Reserved.

#include <iomanip>
#include <map>
#include <string>
#include <sstream>
#include <vector>

#include "osquery/core.h"
#include "osquery/database.h"

#define FEATURE(name, reg, bit) std::make_pair(name, std::make_pair(reg, bit))

namespace osquery {
namespace tables {

typedef std::pair<std::string, int> RegisterBit_t;
typedef std::pair<std::string, RegisterBit_t> FeatureDef_t;

std::map<int, std::vector<FeatureDef_t> > kCPUFeatures = {
    {1,
     {
      FEATURE("pae", "edx", 6),
      FEATURE("msr", "edx", 5),
      FEATURE("mtrr", "edx", 12),
      FEATURE("acpi", "edx", 22),
      FEATURE("htt", "edx", 28),
      FEATURE("ia64", "edx", 30),
      FEATURE("vmx", "ecx", 5),
      FEATURE("smx", "ecx", 6),
      FEATURE("hypervisor", "ecx", 31),
      FEATURE("aes", "ecx", 25),
     }},
    {7,
     {
      FEATURE("mpx", "ebx", 14), FEATURE("sha", "ebx", 29),
     }},
};

void cpuid(unsigned int eax, unsigned int ecx, int regs[4]) {
  asm volatile("cpuid"
               : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
               : "a"(eax), "c"(ecx));
}

void registerToString(int reg, std::stringstream& stream) {
  for (size_t i = 0; i < 4; i++) {
    stream << ((char*)&reg)[i];
  }
}

bool isBitSet(size_t bit, unsigned int reg) {
  return ((reg & (1 << bit)) != 0);
}

Status genVendorString(QueryData& results) {
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

  return Status(0, "OK");
}

void genFamily(QueryData& results) {
  int regs[4] = {-1};

  cpuid(1, 0, regs);
  int family = regs[0] & 0xf00;

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

QueryData genCPUID() {
  QueryData results;

  if (!genVendorString(results).ok()) {
    return results;
  }

  // Get the CPU meta-data about the model, stepping, family.
  genFamily(results);

  int regs[4] = {-1};
  int feature_register, feature_bit;
  for (auto& feature_set : kCPUFeatures) {
    int eax = feature_set.first;
    cpuid(eax, 0, regs);

    for (auto& feature : feature_set.second) {
      Row r;

      r["feature"] = feature.first;

      // Get the return register holding the feature bit.
      feature_register = 0;
      if (feature.second.first == "edx") {
        feature_register = 3;
      } else if (feature.second.first == "ebx") {
        feature_register = 1;
      } else if (feature.second.first == "ecx") {
        feature_register = 2;
      }

      feature_bit = feature.second.second;
      r["value"] = isBitSet(feature_bit, regs[feature_register]) ? "1" : "0";
      r["output_register"] = feature.second.first;
      r["output_bit"] = INTEGER(feature_bit);
      r["input_eax"] = boost::lexical_cast<std::string>(eax);
      results.push_back(r);
    }
  }

  return results;
}
}
}
