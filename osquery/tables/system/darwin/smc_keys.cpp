/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <sstream>

#include <IOKit/IOKitLib.h>

#include <boost/algorithm/hex.hpp>
#include <boost/format.hpp>
#include <boost/noncopyable.hpp>

#include <osquery/core/tables.h>

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
    "Th1H", "Th2H", "Tm0P", "Ts0P", "Tb0P", "TL0P", "TW0P", "TH0P",
    "TH1P", "TH2P", "TH3P", "TO0P", "TB0T", "TB1T", "TB2T", "TB3T",
    "Tp0C", "Tp1P", "Tp1C", "Tp2P", "Tp3P", "Tp4P", "Tp5P", "TS0C", "TA0S",
    "TA1S", "TA2S", "TA3S",
};

std::set<std::string> kSMCVoltageKeys = {
    "VC0C", "VC1C", "VC2C", "VC3C", "VC4C", "VC5C", "VC6C", "VC7C", "VV1R",
    "VG0C", "VM0R", "VN1R", "VN0C", "VD0R", "VD5R", "VP0R", "Vp0C", "VV2S",
    "VR3R", "VV1S", "VH05", "VV9S", "VD2R", "VV7S", "VV3S", "VV8S", "VeES",
    "VBAT", "Vb0R",
};

std::set<std::string> kSMCCurrentKeys = {
    "IC0C", "IC1C", "IC2C", "IC0R", "IC5R", "IC8R", "IC0G", "IC0M", "IG0C",
    "IM0C", "IM0R", "IN0C", "ID0R", "ID5R", "IO0R", "IB0R", "IPBR",
};

std::set<std::string> kSMCPowerKeys = {
    "PC0C", "PC1C", "PC2C", "PC3C", "PC4C", "PC5C", "PC6C", "PC7C", "PCPC",
    "PCPG", "PCPD", "PCTR", "PCPL", "PC1R", "PC5R", "PGTR", "PG0R", "PM0R",
    "PN0C", "PN1R", "PC0R", "PD0R", "PD5R", "PH02", "PH05", "Pp0R", "PD2R",
    "PO0R", "PBLC", "PB0R", "PDTR", "PSTR",
};

std::map<std::string, std::string> kSMCFanSpeeds = {
    {"F%dID", "name"},
    {"F%dAc", "actual"},
    {"F%dMn", "min"},
    {"F%dMx", "max"},
    {"F%dTg", "target"}};
// clang-format on

/// See the following article for reference: http://superuser.com/a/967056
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
    {"TA3S", "PCI Slot 2 Pos 2"},
    {"VC0C", "CPU Core 1"},
    {"VC1C", "CPU Core 2"},
    {"VC2C", "CPU Core 3"},
    {"VC3C", "CPU Core 4"},
    {"VC4C", "CPU Core 5"},
    {"VC5C", "CPU Core 6"},
    {"VC6C", "CPU Core 7"},
    {"VC7C", "CPU Core 8"},
    {"VV1R", "CPU VTT"},
    {"VG0C", "GPU Core"},
    {"VM0R", "Memory"},
    {"VN1R", "PCH"},
    {"VN0C", "MCH"},
    {"VD0R", "Mainboard S0 Rail"},
    {"VD5R", "Mainboard S5 Rail"},
    {"VP0R", "12V Rail"},
    {"Vp0C", "12V Vcc"},
    {"VV2S", "Main 3V"},
    {"VR3R", "Main 3.3V"},
    {"VV1S", "Main 5V"},
    {"VH05", "Main 5V"},
    {"VV9S", "Main 12V"},
    {"VD2R", "Main 12V"},
    {"VV7S", "Auxiliary 3V"},
    {"VV3S", "Standby 3V"},
    {"VV8S", "Standby 5V"},
    {"VeES", "PCIe 12V"},
    {"VBAT", "Battery"},
    {"Vb0R", "CMOS Battery"},
    {"IC0C", "CPU Core"},
    {"IC1C", "CPU VccIO"},
    {"IC2C", "CPU VccSA"},
    {"IC0R", "CPU Rail"},
    {"IC5R", "CPU DRAM"},
    {"IC8R", "CPU PLL"},
    {"IC0G", "CPU GFX"},
    {"IC0M", "CPU Memory"},
    {"IG0C", "GPU Rail"},
    {"IM0C", "Memory Controller"},
    {"IM0R", "Memory Rail"},
    {"IN0C", "MCH"},
    {"ID0R", "Mainboard S0 Rail"},
    {"ID5R", "Mainboard S5 Rail"},
    {"IO0R", "Misc. Rail"},
    {"IB0R", "Battery Rail"},
    {"IPBR", "Charger BMON"},
    {"PC0C", "CPU Core 1"},
    {"PC1C", "CPU Core 2"},
    {"PC2C", "CPU Core 3"},
    {"PC3C", "CPU Core 4"},
    {"PC4C", "CPU Core 5"},
    {"PC5C", "CPU Core 6"},
    {"PC6C", "CPU Core 7"},
    {"PC7C", "CPU Core 8"},
    {"PCPC", "CPU Cores"},
    {"PCPG", "CPU GFX"},
    {"PCPD", "CPU DRAM"},
    {"PCTR", "CPU Total"},
    {"PCPL", "CPU Total"},
    {"PC1R", "CPU Rail"},
    {"PC5R", "CPU S0 Rail"},
    {"PGTR", "GPU Total"},
    {"PG0R", "GPU Rail"},
    {"PM0R", "Memory Rail"},
    {"PN0C", "MCH"},
    {"PN1R", "PCH Rail"},
    {"PC0R", "Mainboard S0 Rail"},
    {"PD0R", "Mainboard S0 Rail"},
    {"PD5R", "Mainboard S5 Rail"},
    {"PH02", "Main 3.3V Rail"},
    {"PH05", "Main 5V Rail"},
    {"Pp0R", "12V Rail"},
    {"PD2R", "Main 12V Rail"},
    {"PO0R", "Misc. Rail"},
    {"PBLC", "Battery Rail"},
    {"PB0R", "Battery Rail"},
    {"PDTR", "DC In Total"},
    {"PSTR", "System Total"}};

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

  /// Shutdown the IOKit connection.
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
    total += (unsigned char)(str[i]) << (size - 1 - i) * 8;
  }
  return total;
}

float getConvertedValue(const std::string &smcType, const std::string &smcVal) {
  // Convert hex string to decimal.
  std::string val;
  try {
    val = boost::algorithm::unhex(smcVal);
  } catch (const boost::algorithm::hex_decode_error &e) {
    return -1.0;
  }

  if (val.size() < 2) {
    return -1.0;
  }

  float convertedVal = -1.0;
  if (smcType == "sp78") {
    convertedVal = (val[0] * 256 + val[1]) / 256.0;
  } else if (smcType == "fpe2") {
    convertedVal = (int(val[0]) << 6) + (int(val[1]) >> 2);
  } else if (smcType == "sp5a") {
    convertedVal = (val[0] * 256 + val[1]) / 1024.0;
  }

  return convertedVal;
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
    context.iteritems(
        "key", EQUALS, ([&smc, &results](const std::string& expr) {
          bool hidden = (kSMCHiddenKeys.count(expr) > 0);
          genSMCKey(expr, smc, results, hidden);
        }));
    return results;
  }

  // Otherwise the default scan will enumerate all keys (maybe 'hidden' keys).
  // 'Maybe' because the hidden keys are only reported in the SMC is unlocked.
  auto keys = smc.getKeys();
  for (const auto &key : keys) {
    genSMCKey(key, smc, results);
  }

  // Potentially report duplicated 'hidden' keys.
  for (const auto &hidden_key : kSMCHiddenKeys) {
    genSMCKey(hidden_key, smc, results, true);
  }

  return results;
}

inline QueryData getSMCKeysUsingPredicate(
    const QueryContext &context,
    const std::set<std::string> &keys,
    std::function<void(const Row &r, QueryData &results)> predicate) {
  SMCHelper smc;
  if (!smc.open()) {
    return {};
  }

  QueryData results;
  auto wrapped = ([&smc, &keys, &results, &predicate](const std::string &expr) {
    // Check if the expression key is within the category of 'keys'.
    if (keys.count(expr) > 0) {
      QueryData key_data;
      // Generate the basic SMC key data for this input expression.
      genSMCKey(expr, smc, key_data);
      if (!key_data.empty()) {
        // If data was found, apply the predicate parser.
        // This will 'transform' the SMC key data into a parsed row.
        predicate(key_data.back(), results);
      }
    }
  });

  if (context.hasConstraint("key", EQUALS)) {
    context.iteritems("key", EQUALS, wrapped);
  } else {
    // Perform a full scan of the keys category.
    for (const auto &key : keys) {
      wrapped(key);
    }
  }

  return results;
}

void genTemperature(const Row &row, QueryData &results) {
  auto &smcRow = row;
  if (smcRow.at("value").empty()) {
    return;
  }

  Row r;
  r["key"] = smcRow.at("key");
  r["name"] = kSMCKeyDescriptions.at(smcRow.at("key"));

  float celsiusValue = getConvertedValue(smcRow.at("type"), smcRow.at("value"));
  float fahrenheitValue = (celsiusValue * (9.0 / 5.0)) + 32;

  std::stringstream buff;
  std::stringstream buff2;
  buff << std::fixed << std::setprecision(1) << celsiusValue;
  buff2 << std::fixed << std::setprecision(1) << fahrenheitValue;
  r["celsius"] = buff.str();
  r["fahrenheit"] = buff2.str();

  results.push_back(r);
}

QueryData genTemperatureSensors(QueryContext &context) {
  return getSMCKeysUsingPredicate(context, kSMCTemperatureKeys, genTemperature);
}

void genPower(const Row &row, QueryData &results) {
  auto &smcRow = row;
  if (smcRow.at("value").empty()) {
    return;
  }

  Row r;
  r["key"] = smcRow.at("key");
  r["name"] = kSMCKeyDescriptions.at(smcRow.at("key"));

  float value = getConvertedValue(smcRow.at("type"), smcRow.at("value"));

  std::stringstream buff;
  buff << std::fixed << std::setprecision(2) << value;
  r["value"] = buff.str();

  results.push_back(r);
}

QueryData genPowerSensors(QueryContext &context) {
  // Define a 'category' for sets of keys.
  std::string category = "";

  // Create a predicate wrapper that injects a category.
  auto wrapper = ([&category](const Row &row, QueryData &results) {
    genPower(row, results);
    if (results.size() > 0) {
      // This column does not normally exist from SMC, we intercept and append.
      results.back()["category"] = category;
    }
  });

  category = "power";
  auto power = getSMCKeysUsingPredicate(context, kSMCPowerKeys, wrapper);

  category = "current";
  auto current = getSMCKeysUsingPredicate(context, kSMCCurrentKeys, wrapper);

  category = "voltage";
  auto voltage = getSMCKeysUsingPredicate(context, kSMCVoltageKeys, wrapper);

  // Add them together:
  power.insert(power.end(), current.begin(), current.end());
  power.insert(power.end(), voltage.begin(), voltage.end());
  return power;
}

std::string getFanName(const std::string &smcVal) {
  // Ensure smc value is 32 char string (16 bytes).
  if (smcVal.size() != 32) {
    return "";
  }

  // The last 12 bytes (24 chars) contains the fan name.
  // See https://github.com/beltex/SMCKit/blob/master/SMCKit/SMC.swift#L674-L698
  std::string val;
  try {
    val = boost::algorithm::unhex(smcVal.substr(8, 24));
  } catch (const boost::algorithm::hex_decode_error &e) {
    return "";
  }

  return val;
}

QueryData genFanSpeedSensors(QueryContext &context) {
  QueryData results;

  SMCHelper smc;
  if (!smc.open()) {
    return {};
  }

  // Get number of fans.
  QueryData key_data;
  genSMCKey("FNum", smc, key_data);
  if (key_data.empty()) {
    // The SMC search for key information failed.
    return results;
  }

  auto &smcRow = key_data.back();
  if (smcRow["value"].empty()) {
    return results;
  }

  // Get attributes for each fan.
  int numFans = std::stoi(smcRow["value"]);
  for (int fanIdx = 0; fanIdx < numFans; fanIdx++) {
    Row r;
    r["fan"] = std::to_string(fanIdx);

    for (const auto &smcFanSpeedKey : kSMCFanSpeeds) {
      r[smcFanSpeedKey.second] = INTEGER(0);

      std::stringstream key;
      key << boost::format(smcFanSpeedKey.first) % fanIdx;

      QueryData fan_data;
      genSMCKey(key.str(), smc, fan_data);
      if (fan_data.empty()) {
        continue;
      }

      auto& fdb = fan_data.back();
      if (fdb["value"].empty()) {
        continue;
      }

      if (smcFanSpeedKey.second == "name") {
        r[smcFanSpeedKey.second] = getFanName(fdb["value"]);
      } else {
        float fanSpeed = getConvertedValue(fdb["type"], fdb["value"]);
        r[smcFanSpeedKey.second] = INTEGER(fanSpeed);
      }
    }

    results.push_back(r);
  }

  return results;
}
}
}
