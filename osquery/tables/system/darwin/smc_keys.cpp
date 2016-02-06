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

#include <boost/algorithm/hex.hpp>
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

// clang-format off
std::set<std::string> kSMCTemperatureKeys = {
    "TCXC", "TCXc", "TC0P", "TC0H", "TC0D", "TC0E", "TC0F", "TC1C", "TC2C",
    "TC3C", "TC4C", "TC5C", "TC6C", "TC7C", "TC8C", "TCAH", "TCAD", "TC1P",
    "TC1H", "TC1D", "TC1E", "TC1F", "TCBH", "TCBD", "TCSC", "TCSc", "TCSA",
    "TCGC", "TCGc", "TG0P", "TG0D", "TG1D", "TG0H", "TG1H", "Ts0S", "TM0P",
    "TM1P", "TM8P", "TM9P", "TM0S", "TM1S", "TM8S", "TM9S", "TN0D", "TN0P",
    "TN1P", "TN0C", "TN0H", "TP0D", "TPCD", "TP0P", "TA0P", "TA1P", "Th0H",
    "Th1H", "Th2H", "Tm0P", "Tp0P", "Ts0P", "Tb0P", "TL0P", "TW0P", "TH0P",
    "TH1P", "TH2P", "TH3P", "TO0P", "TB0T", "TB1T", "TB2T", "TB3T", "Tp0P",
    "Tp0C", "Tp1P", "Tp1C", "Tp2P", "Tp3P", "Tp4P", "Tp5P", "TS0C", "TA0S",
    "TA1S", "TA2S", "TA3S",
};
// clang-format on

// http://superuser.com/a/967056
const std::map<std::string, std::string> kSMCKeyDescriptions = {
    {"TCXC", "PECI CPU"},
    {"TCXc", "PECI CPU"},
    {"TC0P", "CPU 1 Proximity"},
    {"TC0H", "CPU 1 Heatsink"},
    {"TC0D", "CPU 1 Package"},
    {"TC0E", "CPU 1"},
    {"TC0F", "CPU 1"},
    {"TC1C", "CPU Core 1"},
    {"TC2C", "CPU Core 2"},
    {"TC3C", "CPU Core 3"},
    {"TC4C", "CPU Core 4"},
    {"TC5C", "CPU Core 5"},
    {"TC6C", "CPU Core 6"},
    {"TC7C", "CPU Core 7"},
    {"TC8C", "CPU Core 8"},
    {"TCAH", "CPU 1 Heatsink Alt."},
    {"TCAD", "CPU 1 Package Alt."},
    {"TC1P", "CPU 2 Proximity"},
    {"TC1H", "CPU 2 Heatsink"},
    {"TC1D", "CPU 2 Package"},
    {"TC1E", "CPU 2"},
    {"TC1F", "CPU 2"},
    {"TCBH", "CPU 2 Heatsink Alt."},
    {"TCBD", "CPU 2 Package Alt."},
    {"TCSC", "PECI SA"},
    {"TCSc", "PECI SA"},
    {"TCSA", "PECI SA"},
    {"TCGC", "PECI GPU"},
    {"TCGc", "PECI GPU"},
    {"TG0P", "GPU Proximity"},
    {"TG0D", "GPU Die"},
    {"TG1D", "GPU Die"},
    {"TG0H", "GPU Heatsink"},
    {"TG1H", "GPU Heatsink"},
    {"Ts0S", "Memory Proximity"},
    {"TM0P", "Mem Bank A1"},
    {"TM1P", "Mem Bank A2"},
    {"TM8P", "Mem Bank B1"},
    {"TM9P", "Mem Bank B2"},
    {"TM0S", "Mem Module A1"},
    {"TM1S", "Mem Module A2"},
    {"TM8S", "Mem Module B1"},
    {"TM9S", "Mem Module B2"},
    {"TN0D", "Northbridge Die"},
    {"TN0P", "Northbridge Proximity 1"},
    {"TN1P", "Northbridge Proximity 2"},
    {"TN0C", "MCH Die"},
    {"TN0H", "MCH Heatsink"},
    {"TP0D", "PCH Die"},
    {"TPCD", "PCH Die"},
    {"TP0P", "PCH Proximity"},
    {"TA0P", "Airflow 1"},
    {"TA1P", "Airflow 2"},
    {"Th0H", "Heatpipe 1"},
    {"Th1H", "Heatpipe 2"},
    {"Th2H", "Heatpipe 3"},
    {"Tm0P", "Mainboard Proximity"},
    {"Tp0P", "Powerboard Proximity"},
    {"Ts0P", "Palm Rest"},
    {"Tb0P", "BLC Proximity"},
    {"TL0P", "LCD Proximity"},
    {"TW0P", "Airport Proximity"},
    {"TH0P", "HDD Bay 1"},
    {"TH1P", "HDD Bay 2"},
    {"TH2P", "HDD Bay 3"},
    {"TH3P", "HDD Bay 4"},
    {"TO0P", "Optical Drive"},
    {"TB0T", "Battery TS_MAX"},
    {"TB1T", "Battery 1"},
    {"TB2T", "Battery 2"},
    {"TB3T", "Battery"},
    {"Tp0P", "Power Supply 1"},
    {"Tp0C", "Power Supply 1 Alt."},
    {"Tp1P", "Power Supply 2"},
    {"Tp1C", "Power Supply 2 Alt."},
    {"Tp2P", "Power Supply 3"},
    {"Tp3P", "Power Supply 4"},
    {"Tp4P", "Power Supply 5"},
    {"Tp5P", "Power Supply 6"},
    {"TS0C", "Expansion Slots"},
    {"TA0S", "PCI Slot 1 Pos 1"},
    {"TA1S", "PCI Slot 1 Pos 2"},
    {"TA2S", "PCI Slot 2 Pos 1"},
    {"TA3S", "PCI Slot 2 Pos 2"}};

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

void genTemperature(const std::string &key,
                    const SMCHelper &smc,
                    QueryData &results) {
  QueryData key_data;
  genSMCKey(key, smc, key_data);

  if (key_data.empty()) {
    // The SMC search for key information failed.
    return;
  }

  auto &smcRow = key_data.back();
  if (smcRow["value"].empty()) {
    return;
  }

  Row r;
  r["key"] = smcRow["key"];
  r["name"] = kSMCKeyDescriptions.at(smcRow["key"]);

  // Convert hex string to decimal.
  std::string val;
  try {
    val = boost::algorithm::unhex(smcRow["value"]);
  } catch (const boost::algorithm::hex_decode_error &e) {
    return;
  }

  if (val.size() < 2) {
    return;
  }

  int intValue = (val[0] * 256 + val[1]);
  float floatValueCelsius = intValue / 256.0;
  float floatValueFahrenheit = (floatValueCelsius * (9 / 5)) + 32;

  std::stringstream buff1;
  std::stringstream buff2;
  buff1 << std::fixed << std::setprecision(1) << floatValueCelsius;
  buff2 << std::fixed << std::setprecision(1) << floatValueFahrenheit;
  r["celsius"] = buff1.str();
  r["fahrenheit"] = buff2.str();

  results.push_back(r);
}

QueryData getTemperatures(QueryContext &context) {
  QueryData results;

  SMCHelper smc;
  if (!smc.open()) {
    return {};
  }

  if (context.hasConstraint("key", EQUALS)) {
    context.forEachConstraint("key",
                              EQUALS,
                              ([&smc, &results](const std::string &expr) {
                                if (kSMCTemperatureKeys.count(expr) > 0) {
                                  genTemperature(expr, smc, results);
                                }
                              }));
  } else {
    // Perform a full scan of temperature keys.
    for (const auto &smcTempKey : kSMCTemperatureKeys) {
      genTemperature(smcTempKey, smc, results);
    }
  }

  return results;
}
}
}
