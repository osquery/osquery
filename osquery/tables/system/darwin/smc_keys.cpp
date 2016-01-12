/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iomanip>
#include <sstream>

#include <IOKit/IOKitLib.h>

#include <boost/noncopyable.hpp>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

#define KERNEL_INDEX_SMC 2

typedef struct { char bytes[32]; } SMCBytes_t;
typedef struct { char bytes[5]; } UInt32Char_t;

enum class SMCCMDType : char {
  READ_BYTES = 5,
  WRITE_BYTES = 6,
  READ_INDEX = 8,
  READ_KEYINFO = 9,
  READ_PLIMIT = 11,
  READ_VERS = 12,
};

typedef struct {
  char major;
  char minor;
  char build;
  char reserved[1];
  UInt16 release;
} SMCKeyDataVersion_t;

typedef struct {
  UInt16 version;
  UInt16 length;
  UInt32 cpuPLimit;
  UInt32 gpuPLimit;
  UInt32 memPLimit;
} SMCKeyDataLimits_t;

typedef struct {
  UInt32 dataSize;
  UInt32 dataType;
  char dataAttributes;
} SMCKeyDataKeyInfo_t;

typedef struct {
  UInt32 key;
  SMCKeyDataVersion_t vers;
  SMCKeyDataLimits_t pLimitData;
  SMCKeyDataKeyInfo_t keyInfo;
  char result;
  char status;
  SMCCMDType data8;
  UInt32 data32;
  SMCBytes_t bytes;
} SMCKeyData_t;

typedef struct {
  UInt32Char_t key;
  UInt32 dataSize;
  UInt32Char_t dataType;
  SMCBytes_t bytes;
} SMCValue_t;

/// Warning: OSK0, OSK1 are removed from this list.
std::set<std::string> kSMCHiddenKeys = {
    "CRDP", "FPOR", "KPPW", "KPST", "MOJO", "MSSN", "zCRS",
};

class SMCHelper : private boost::noncopyable {
 public:
  virtual ~SMCHelper() {
    if (connection_ != 0) {
      close();
    }
  }

  /**
   * @brief Open the IOKit master port, device driver, and service.
   *
   * This will find the userland SMC interface driver and open the service.
   * It will remain open until the helper is deleted.
   */
  bool open();
  void close() { IOServiceClose(connection_); }

  /// Read a given SMC key into an output parameter value.
  bool read(const std::string &key, SMCValue_t *val) const;

  /// Read all keys (a service API call) into a string vector.
  std::vector<std::string> getKeys() const;

 private:
  /// Perform an API call to the IOKit AppleSMC service.
  kern_return_t call(uint32_t selector,
                     SMCKeyData_t *in,
                     SMCKeyData_t *out) const;

  /// Read the size of the internal SMC key structure.
  size_t getKeysCount() const;

 private:
  /// IOKit master port.
  mach_port_t master_port_{0};
  /// IOKit service connection.
  io_connect_t connection_{0};
};

bool SMCHelper::open() {
  auto result = IOMasterPort(MACH_PORT_NULL, &master_port_);
  if (result != kIOReturnSuccess) {
    return false;
  }

  // The IOKit-based kernel extension will provide the IOKit service: AppleSMC.
  auto matches = IOServiceMatching("AppleSMC");
  if (matches == nullptr) {
    return false;
  }

  io_iterator_t iterator;
  result = IOServiceGetMatchingServices(master_port_, matches, &iterator);
  if (result != kIOReturnSuccess) {
    return false;
  }

  auto device = IOIteratorNext(iterator);
  IOObjectRelease((io_object_t)iterator);
  if (device == 0) {
    return false;
  }

  result = IOServiceOpen(device, mach_task_self(), 0, &connection_);
  IOObjectRelease(device);
  if (result != kIOReturnSuccess) {
    return false;
  }

  return true;
}

kern_return_t SMCHelper::call(uint32_t selector,
                              SMCKeyData_t *in,
                              SMCKeyData_t *out) const {
  size_t in_size = sizeof(SMCKeyData_t);
  size_t out_size = sizeof(SMCKeyData_t);

  return IOConnectCallStructMethod(
      connection_, selector, in, in_size, out, &out_size);
}

inline uint32_t strtoul(const char *str, size_t size, size_t base) {
  uint32_t total = 0;
  for (size_t i = 0; i < size; i++) {
    if (base == 16) {
      total += str[i] << (size - 1 - i) * 8;
    } else {
      total += (unsigned char)(str[i] << (size - 1 - i) * 8);
    }
  }
  return total;
}

bool SMCHelper::read(const std::string &key, SMCValue_t *val) const {
  SMCKeyData_t in;
  SMCKeyData_t out;

  memset(&in, 0, sizeof(SMCKeyData_t));
  memset(&out, 0, sizeof(SMCKeyData_t));
  memset(val, 0, sizeof(SMCValue_t));

  in.key = strtoul(key.c_str(), 4, 16);
  memcpy(val->key.bytes, key.c_str(), 4);
  in.data8 = SMCCMDType::READ_KEYINFO;

  auto result = call(KERNEL_INDEX_SMC, &in, &out);
  if (result != kIOReturnSuccess) {
    return false;
  }

  val->dataSize = out.keyInfo.dataSize;
  val->dataType.bytes[0] = (uint32_t)out.keyInfo.dataType >> 24;
  val->dataType.bytes[1] = (uint32_t)out.keyInfo.dataType >> 16;
  val->dataType.bytes[2] = (uint32_t)out.keyInfo.dataType >> 8;
  val->dataType.bytes[3] = (uint32_t)out.keyInfo.dataType;
  in.keyInfo.dataSize = val->dataSize;
  in.data8 = SMCCMDType::READ_BYTES;

  result = call(KERNEL_INDEX_SMC, &in, &out);
  if (result != kIOReturnSuccess) {
    return false;
  }

  memcpy(val->bytes.bytes, out.bytes.bytes, sizeof(out.bytes));
  return true;
}

size_t SMCHelper::getKeysCount() const {
  SMCValue_t val;
  read("#KEY", &val);
  return ((int)val.bytes.bytes[2] << 8) + ((unsigned)val.bytes.bytes[3] & 0xff);
}

std::vector<std::string> SMCHelper::getKeys() const {
  std::vector<std::string> keys;
  size_t totalKeys = getKeysCount();
  for (size_t i = 0; i < totalKeys; i++) {
    SMCKeyData_t in;
    SMCKeyData_t out;

    memset(&in, 0, sizeof(SMCKeyData_t));
    memset(&out, 0, sizeof(SMCKeyData_t));

    in.data8 = SMCCMDType::READ_INDEX;
    in.data32 = i;

    auto result = call(KERNEL_INDEX_SMC, &in, &out);
    if (result != kIOReturnSuccess) {
      continue;
    }

    UInt32Char_t key;
    key.bytes[0] = (uint32_t)out.key >> 24;
    key.bytes[1] = (uint32_t)out.key >> 16;
    key.bytes[2] = (uint32_t)out.key >> 8;
    key.bytes[3] = (uint32_t)out.key;
    key.bytes[4] = 0;
    keys.push_back(key.bytes);
  }
  return keys;
}

inline float strtof(const char *str, size_t size, size_t e) {
  float total = 0;
  for (size_t i = 0; i < size; i++) {
    if (i == (size - 1)) {
      total += (str[i] & 0xff) >> e;
    } else {
      total += str[i] << (size - 1 - i) * (8 - e);
    }
  }
  return total;
}

void genSMCKey(const std::string &key,
               const SMCHelper &smc,
               QueryData &results,
               bool hidden = false) {
  Row r;
  r["key"] = key;
  r["hidden"] = (hidden) ? "1" : "0";

  SMCValue_t value;
  memset(&value, 0, sizeof(SMCValue_t));
  smc.read(key, &value);
  r["type"] = value.dataType.bytes;
  r["size"] = INTEGER(value.dataSize);
  if (r["type"] == "ui8" || r["type"] == "ui16" || r["type"] == "ui32") {
    r["value"] = std::to_string(strtoul(value.bytes.bytes, value.dataSize, 10));
  } else if (r["type"] == "fpe2") {
    r["value"] = std::to_string(strtof(value.bytes.bytes, value.dataSize, 10));
  } else {
    std::stringstream hex;
    for (size_t i = 0; i < value.dataSize; i++) {
      uint32_t hex_value = (uint8_t)value.bytes.bytes[i];
      hex << std::hex << std::setw(2) << std::setfill('0') << hex_value;
    }
    r["value"] = hex.str();
  }
  results.push_back(r);
}

QueryData genSMCKeys(QueryContext &context) {
  QueryData results;

  SMCHelper smc;
  if (!smc.open()) {
    return {};
  }

  // If the query is requesting an SMC key by name within the predicate.
  if (context.hasConstraint("key", EQUALS)) {
    context.forEachConstraint("key",
                              EQUALS,
                              ([&smc, &results](const std::string &expr) {
                                bool hidden = (kSMCHiddenKeys.count(expr) > 0);
                                genSMCKey(expr, smc, results, hidden);
                              }));
    return results;
  }

  // Otherwise the default scan will enumerate all keys then attempt a static
  // list if 'hidden' keys.
  auto keys = smc.getKeys();
  for (const auto &key : keys) {
    genSMCKey(key, smc, results);
  }

  for (const auto &hidden_key : kSMCHiddenKeys) {
    genSMCKey(hidden_key, smc, results, true);
  }

  return results;
}
}
}
