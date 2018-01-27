/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional
 * grant of patent rights can be found in the PATENTS file in the same
 * directory.
 *
 */

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_lanparm.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_user.h>
#include <OpenIPMI/ipmiif.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/config/parsers/ipmi.h"
#include "osquery/tables/ipmi/client.h"

namespace osquery {

#define IPMI_DEFAULT_INIT_TIMEOUT 360000
#define IPMI_CLEANUP_DURATION 120000
#define IPMI_QUERY_LAN_TIMEOUT 1000
#define IPMI_QUERY_THRESHOLD_SENSORS_TIMEOUT 1000
#define IPMI_QUERY_FRU_TIMEOUT 100
#define IPMI_QUERY_MC_TIMEOUT 100
#define NOERR 0

/**
 * @brief parmData encapsulates things that are required for retrieving
 * LANPARM
 *
 * @param client pointer to IPMIClient instance
 * @param mcKey unique key to identify the MC
 * @parm colName the osquery table column name of the LANPARM
 *
 * @parm parm OpenIPMI identifier for the LANPARM
 *
 */
struct parmData {
  IPMIClient* client;
  std::string mcKey;
  std::string colName;
  unsigned int parm;

  parmData() : client(nullptr), mcKey(""), colName(""), parm(999) {}
};

/// Unique pointer deleter for os_handler_t*
const auto kFreeOSHandle = [](os_handler_t* h) {
  if (h != nullptr) {
    ipmi_posix_free_os_handler(h);
  }
};

/// Unique pointer deleter for ipmi_lanparm_t*
const auto kFreeLANParm = [](ipmi_lanparm_t* lp) {
  if (lp != nullptr) {
    // Utilizing the ipmi_lanparm_destroy from
    // https://github.com/wrouesnel/openipmi/blob/master/include/OpenIPMI/ipmi_lanparm.h#L62
    // results in segfaults on  process exit.  Leak check utilzing Valgrind
    // showed no mem leaks utilizing the ref/defref API, but does intermittently
    // show bytes as possibly lost.
    ipmi_lanparm_deref(lp);
  }
};

/// Gets timeout value from configuration.
static inline size_t getTimeoutConfig(const std::string&& name,
                                      size_t defaultTimeout) {
  auto parser = Config::getParser("ipmi");
  if (parser != nullptr && parser.get() != nullptr) {
    const auto& config = parser->getData().get_child(
        kIPMIConfigParserRootKey, boost::property_tree::ptree("UNEXPECTED"));
    if (config.get_value("") == "UNEXPECTED") {
      LOG(WARNING) << "Could not load ipmi configuration root key: "
                   << kIPMIConfigParserRootKey;
    }

    return config.get_child(name, boost::property_tree::ptree())
        .get_value<size_t>(defaultTimeout);
  }
}

/**
 * @brief retrieves name of MC
 *
 * @param mc pointer to OPENIPMI ipmi_mc_t
 * @param defaultName fallback name if the MC name is unable to be retrieved
 *
 * @return MC name as std::string
 */
static inline std::string getMCName(
    ipmi_mc_t* mc, const std::string& defaultName = "missing") {
  char name[IPMI_MC_NAME_LEN] = {0};
  auto len = ipmi_mc_get_name(mc, name, IPMI_MC_NAME_LEN);
  if (len < 1) {
    return defaultName;
  }

  return name;
}

/**
 * @brief generates key to uniquely identify an MC instance
 *
 * @param mc pointer to OPENIPMI ipmi_mc_t
 *
 * @return unique key for MC as std::string
 */
static inline std::string getMCKey(ipmi_mc_t* mc) {
  return getMCName(mc) + "-" + std::to_string(ipmi_mc_device_id(mc));
}

/// Callback for handling logs coming from OpenIPMI. Only log error level and
/// above
void ipmiLoggerCB(os_handler_t* handler,
                  const char* format,
                  enum ipmi_log_type_e logType,
                  va_list ap) {
  switch (logType) {
  case IPMI_LOG_SEVERE:
  case IPMI_LOG_FATAL:
  case IPMI_LOG_ERR_INFO: {
    /* We use C style data structures and string functions because we are
     * given C style formatters and variadic functions */
    const size_t max = 1024;
    char buf[max] = {0};
    vsnprintf(buf, max, format, ap);
    LOG(ERROR) << buf;
  }
  default:
    // Silence all other log levels
    break;
  }
}

/// Converts bytes from first to length len to CIDR format in std::string.
static inline std::string toCIDR(const unsigned char* first,
                                 const unsigned int len) {
  if (len != 5) {
    LOG(ERROR) << "Unexpected return data length for CIDR PARM data of " << len
               << "; expected 5";
    return "";
  }

  std::stringstream cidr;
  for (unsigned int i = 1; i < len; i++) {
    cidr << static_cast<int>(first[i]);
    if (i != len - 1) {
      cidr << ".";
    }
  }

  return cidr.str();
}

/// Converts bytes from first to length len to MAC format in std::string.
static inline std::string toMAC(const unsigned char* first,
                                const unsigned int len) {
  if (len != 7) {
    LOG(ERROR) << "Unexpected return data length for MAC address PARM data of "
               << len << "; expected 7";
    return "";
  }

  std::stringstream mac;
  for (unsigned int i = 1; i < len; i++) {
    mac << std::hex << static_cast<int>(first[i]);
    if (i != len - 1) {
      mac << ":";
    }
  }

  return mac.str();
}

/// Converts bytes to stringified IP address source.
static inline std::string toAddressSrc(const unsigned char* val,
                                       const unsigned int len) {
  if (len != 2) {
    LOG(WARNING) << "Expected data length of 2 for "
                    "IPMI_LANPARM_IP_ADDRESS_SRC, but got "
                 << std::to_string(len);
    return "";
  }

  switch (val[1] & 7) {
  case IPMI_LANPARM_IP_ADDR_SRC_STATIC:
    return "static";

  case IPMI_LANPARM_IP_ADDR_SRC_DHCP:
    return "dhcp";

  case IPMI_LANPARM_IP_ADDR_SRC_BIOS:
    return "bios";

  case IPMI_LANPARM_IP_ADDR_SRC_OTHER:
    return "other";

  default:
    return "unknown";
  }
}

/// Converts bytes to stringified set progress state.
static inline std::string toSetInProgress(const unsigned char* val,
                                          const unsigned int len) {
  if (len != 2) {
    LOG(WARNING) << "Expected data length of 2 for "
                    "IPMI_LANPARM_SET_IN_PROGRESS, but got "
                 << std::to_string(len);

    return "";
  }

  switch (val[1] & 3) {
  case 0:
    return "set complete";
  case 1:
    return "set in progress";
  case 2:
    return "commit write";
  default:
    return "unknown";
  }
}

/* @brief Handles the unlocking of ipmi_lanparm_t*.
 *
 * @param lp ipmi_lanpar_t* to unlock
 *
 * Debug logs if error is encountered, since depending on system this can
 * error out and be inconsequential.
 */
static inline void unlockLANPARM(ipmi_lanparm_t* lp) {
  auto rv =
      ipmi_lan_clear_lock(lp,
                          NULL,
                          [](ipmi_lanparm_t* lanparm, int err, void* data) {
                            TLOG << "Unlocking OpenIPMI LANParm from callback";
                            if (err != 0) {
                              TLOG << "Unexpected error while unlocking "
                                      "IPMI LAN PARM : "
                                   << strerror(err);
                            }
                          },
                          NULL);

  if (rv != 0) {
    LOG(ERROR) << "Could not clear ipmi lan lock: " << strerror(rv);
  }
}

/// Gets a ipmi_lanparm_t*.  Does all registration needed with IPMIClient.
void getPARM(ipmi_lanparm_t* lp,
             unsigned int parm,
             const std::string& key,
             const std::string& colName,
             IPMIClient* client) {
  parmData* data = new parmData;
  data->client = client;
  data->mcKey = key;
  data->colName = colName;
  data->parm = parm;
  client->pushParmData(data);

  auto rv = ipmi_lanparm_get_parm(
      lp,
      parm,
      0,
      0,
      [](ipmi_lanparm_t* lanparm,
         int err,
         unsigned char* parmVal,
         unsigned int dataLen,
         void* retData) {

        parmData* d = (parmData*)retData;
        std::unique_ptr<parmData, std::function<void(parmData*)>> freeParm(
            d, [](parmData* parm) {
              TLOG << "Freeing OpenIPMI LANParm from unique_ptr";
              parm->client->rmParmData(parm);
            });

        if (err != 0) {
          TLOG << "Unexpected error while getting PARM value: "
               << strerror(err);
          return;
        }
        // If there is an error, unlocking will also error out.
        std::unique_ptr<ipmi_lanparm_t, std::function<void(ipmi_lanparm_t*)>>
            unlock(lanparm, unlockLANPARM);

        switch (d->parm) {
        case IPMI_LANPARM_BACKUP_GATEWAY_ADDR:
        case IPMI_LANPARM_IP_ADDRESS:
        case IPMI_LANPARM_DEFAULT_GATEWAY_ADDR:
        case IPMI_LANPARM_SUBNET_MASK:
          d->client->insertRowsQueue(
              d->mcKey, d->colName, toCIDR(parmVal, dataLen));
          break;

        case IPMI_LANPARM_BACKUP_GATEWAY_MAC_ADDR:
        case IPMI_LANPARM_DEFAULT_GATEWAY_MAC_ADDR:
        case IPMI_LANPARM_MAC_ADDRESS:
          d->client->insertRowsQueue(
              d->mcKey, d->colName, toMAC(parmVal, dataLen));
          break;

        case IPMI_LANPARM_IP_ADDRESS_SRC:
          d->client->insertRowsQueue(
              d->mcKey, d->colName, toAddressSrc(parmVal, dataLen));
          break;

        case IPMI_LANPARM_COMMUNITY_STRING: {
          std::string comm(reinterpret_cast<const char*>(parmVal + 1),
                           static_cast<size_t>(dataLen));
          d->client->insertRowsQueue(d->mcKey, d->colName, comm);
          break;
        }

        case IPMI_LANPARM_SET_IN_PROGRESS:
          d->client->insertRowsQueue(
              d->mcKey, d->colName, toSetInProgress(parmVal, dataLen));
          break;

        default:
          LOG(ERROR) << "Got an unexpected LANPARM type: "
                     << std::to_string(d->parm);
          break;
        }

      },
      data);

  if (rv != 0) {
    LOG(ERROR) << "Could not get default gateway lanparm: " << strerror(rv);
  }
}

/*===========================OpenIPMI Callbacks================================
 */

void getLANsCB(ipmi_domain_t* domain, ipmi_mc_t* mc, void* data) {
  IPMIClient* client = reinterpret_cast<IPMIClient*>(data);

  std::string key = getMCKey(mc);
  ipmi_lanparm_t* lp = client->getLANParm(key, mc);
  if (lp == nullptr) {
    LOG(ERROR) << "Could not get ipmi_lanparm_t for mc '" << key;
    return;
  }

  char name[IPMI_MC_NAME_LEN];
  auto len = ipmi_mc_get_name(mc, name, IPMI_MC_NAME_LEN);
  if (len > 0) {
    client->insertRowsQueue(key, "mc_name", name);
  }
  client->insertRowsQueue(key, "mc_id", INTEGER(ipmi_mc_device_id(mc)));

  getPARM(lp, IPMI_LANPARM_IP_ADDRESS, key, "ip", client);

  getPARM(lp, IPMI_LANPARM_DEFAULT_GATEWAY_ADDR, key, "gateway_ip", client);

  getPARM(lp, IPMI_LANPARM_MAC_ADDRESS, key, "mac", client);

  getPARM(lp, IPMI_LANPARM_SUBNET_MASK, key, "subnet_mask", client);

  getPARM(
      lp, IPMI_LANPARM_DEFAULT_GATEWAY_MAC_ADDR, key, "gateway_mac", client);

  getPARM(
      lp, IPMI_LANPARM_BACKUP_GATEWAY_ADDR, key, "backup_gateway_ip", client);

  getPARM(lp,
          IPMI_LANPARM_BACKUP_GATEWAY_MAC_ADDR,
          key,
          "backup_gateway_mac",
          client);

  getPARM(lp, IPMI_LANPARM_IP_ADDRESS_SRC, key, "ip_address_source", client);

  getPARM(
      lp, IPMI_LANPARM_COMMUNITY_STRING, key, "snmp_community_string", client);

  getPARM(lp, IPMI_LANPARM_SET_IN_PROGRESS, key, "set_in_progress", client);
}

void IPMIFullyUpCB(ipmi_domain_t* domain, void* data) {
  TLOG << "OpenIPMI is now fully up";
  auto c = reinterpret_cast<IPMIClient*>(data);
  c->setDomain(domain);

  return;
}

/// Gets the the value suffix for a sensor reading.
std::string getSensorThresholdSuffix(ipmi_sensor_t* sensor) {
  std::string percent, base, mod_use, modifier;

  base = ipmi_sensor_get_base_unit_string(sensor);

  if (ipmi_sensor_get_percentage(sensor)) {
    percent = "%";
  }

  switch (ipmi_sensor_get_modifier_unit_use(sensor)) {
  case IPMI_MODIFIER_UNIT_NONE:
    break;

  case IPMI_MODIFIER_UNIT_BASE_DIV_MOD:
    mod_use = "/";
    modifier = ipmi_sensor_get_modifier_unit_string(sensor);
    break;

  case IPMI_MODIFIER_UNIT_BASE_MULT_MOD:
    mod_use = "*";
    modifier = ipmi_sensor_get_modifier_unit_string(sensor);
    break;
  }

  return percent + " " + base + mod_use + modifier +
         ipmi_sensor_get_rate_unit_string(sensor);
}

void readThresholdSensorCB(ipmi_sensor_t* sensor,
                           int err,
                           enum ipmi_value_present_e value_present,
                           unsigned int raw_value,
                           double val,
                           ipmi_states_t* states,
                           void* data) {
  if (err != 0) {
    LOG(ERROR) << "Could not read sensor: " << strerror(err);
    return;
  }

  Row r;

  auto mc = ipmi_sensor_get_mc(sensor);
  r["mc_name"] = getMCName(mc, "unknown");
  r["mc_id"] = INTEGER(ipmi_mc_device_id(mc));

  const int maxChar = 256;
  char name[maxChar] = {0};
  ipmi_sensor_get_name(sensor, name, maxChar) < 1 ? r["name"] = "missing"
                                                  : r["name"] = name;

  r["sensor_type"] = ipmi_sensor_get_sensor_type_string(sensor);

  switch (value_present) {
  case IPMI_NO_VALUES_PRESENT:
    r["value"] = "no reading available";
    break;

  case IPMI_RAW_VALUE_PRESENT:
    r["value"] = std::to_string(raw_value);
    break;

  default:
    r["value"] = std::to_string(val) + getSensorThresholdSuffix(sensor);
  }

  r["threshold_out_of_range"] =
      (ipmi_is_threshold_out_of_range(states, IPMI_LOWER_NON_CRITICAL) ||
       ipmi_is_threshold_out_of_range(states, IPMI_UPPER_NON_CRITICAL))
          ? "1"
          : "0";

  auto c = reinterpret_cast<IPMIClient*>(data);
  c->insertRowsQueue(r["name"] + "-" + r["mc_name"] + "-" + r["mc_id"], r);
}

void getThresholdSensorCB(ipmi_entity_t* entity, void* data) {
  ipmi_entity_iterate_sensors(
      entity,
      [](ipmi_entity_t* ent, ipmi_sensor_t* sensor, void* data) {
        if (ipmi_sensor_get_event_reading_type(sensor) ==
            IPMI_EVENT_READING_TYPE_THRESHOLD) {
          auto rv =
              ipmi_sensor_get_reading(sensor, readThresholdSensorCB, data);
          if (rv != 0) {
            LOG(ERROR) << "Could not get sensor reading: " << strerror(rv);
          }
        }
      },
      data);
}

/// Walks FRU nodes and appends to Row.
void traverseFRUNodeTree(ipmi_fru_node_t* node, Row& r) {
  time_t tm = {};
  enum ipmi_fru_data_type_e dtype;
  double floatval = 0;
  int intval = 0;
  unsigned int dataLen = 0;
  const char* name = nullptr;

  std::unique_ptr<ipmi_fru_node_t, std::function<void(ipmi_fru_node_t*)>> sNode(
      node, ipmi_fru_put_node);

  for (size_t i = 0;; i++) {
    char* data = nullptr;

    ipmi_fru_node_t* subnode = nullptr;
    auto rv = ipmi_fru_node_get_field(node,
                                      i,
                                      &name,
                                      &dtype,
                                      &intval,
                                      &tm,
                                      &floatval,
                                      &data,
                                      &dataLen,
                                      &subnode);
    if (rv == EINVAL) {
      break;
    }

    std::unique_ptr<char, std::function<void(char*)>> sData(data, [](char* d) {
      if (d) {
        ipmi_fru_data_free(d);
      }
    });

    if (rv != 0) {
      continue;
    }

    std::string colName;
    if (name == nullptr) {
      colName = "missing[" + std::to_string(i) + "]";
    } else {
      colName = name;
    }

    switch (dtype) {
    case IPMI_FRU_DATA_INT:
      r[colName] = INTEGER(intval);
      break;

    case IPMI_FRU_DATA_TIME:
      r[colName] = BIGINT(tm);
      break;

    case IPMI_FRU_DATA_ASCII:
      r[colName] = data;
      break;

    case IPMI_FRU_DATA_BOOLEAN:
      r[colName] = INTEGER(intval);
      break;

    case IPMI_FRU_DATA_FLOAT:
      r[colName] = std::to_string(floatval);
      break;

    case IPMI_FRU_DATA_SUB_NODE:
      traverseFRUNodeTree(subnode, r);
      break;

    default:
      // we don't want any of the other data
      r[colName] = "-1";
      break;
    }
  }
}

void getFRUCB(ipmi_entity_t* entity, void* data) {
  auto fru = ipmi_entity_get_fru(entity);
  if (fru == nullptr) {
    return;
  }

  std::unique_ptr<ipmi_fru_t, std::function<void(ipmi_fru_t*)>> freeFru(
      fru, [](ipmi_fru_t* f) {
        auto rv = ipmi_fru_destroy(f, NULL, NULL);
        if (rv != 0) {
          TLOG << "Could not register ipmi_fru_destroy: " << strerror(rv);
          return;
        }

      });

  Row r;
  r["entity_id"] = INTEGER(ipmi_entity_get_entity_id(entity));
  r["entity_instance"] = INTEGER(ipmi_entity_get_entity_instance(entity));

  char name[IPMI_FRU_NAME_LEN];
  auto len = ipmi_fru_get_name(fru, name, IPMI_FRU_NAME_LEN);
  if (len < 1) {
    r["name"] = "unknown";
  } else {
    r["name"] = name;
  }

  ipmi_fru_node_t* node = nullptr;

  const char* type = "";
  auto rv = ipmi_fru_get_root_node(fru, &type, &node);
  if (rv != 0) {
    TLOG << "Could not get FRU root node: " << strerror(rv);
    return;
  }

  r["type"] = type;
  traverseFRUNodeTree(node, r);

  auto c = reinterpret_cast<IPMIClient*>(data);
  c->insertRowsQueue(
      r["entity_id"] + "-" + r["entity_instance"] + "-" + r["name"], r);
}

static inline std::string toHexString(int&& i) {
  std::stringstream ss;
  ss << std::hex << i;
  return ss.str();
}

void iterateMCsCB(ipmi_domain_t* domain, ipmi_mc_t* mc, void* data) {
  Row r;

  char name[IPMI_MC_NAME_LEN];
  auto len = ipmi_mc_get_name(mc, name, IPMI_MC_NAME_LEN);
  r["name"] = len > 0 ? name : "";

  r["id"] = INTEGER(ipmi_mc_device_id(mc));
  r["device_revision"] = INTEGER(ipmi_mc_device_revision(mc));
  r["device_available"] = INTEGER(ipmi_mc_device_available(mc));
  r["firmware_major_version"] = toHexString(ipmi_mc_major_fw_revision(mc));
  r["firmware_minor_version"] = toHexString(ipmi_mc_minor_fw_revision(mc));
  r["ipmi_major_version"] = INTEGER(ipmi_mc_major_version(mc));
  r["ipmi_minor_version"] = INTEGER(ipmi_mc_minor_version(mc));
  r["iana_manufacturer_id"] = INTEGER(ipmi_mc_manufacturer_id(mc));
  r["product_id"] = INTEGER(ipmi_mc_product_id(mc));
  r["provides_device_sdrs"] = INTEGER(ipmi_mc_provides_device_sdrs(mc));
  r["chassis_support"] = INTEGER(ipmi_mc_chassis_support(mc));
  r["bridge_support"] = INTEGER(ipmi_mc_bridge_support(mc));
  r["ipmb_event_generator_support"] =
      INTEGER(ipmi_mc_ipmb_event_generator_support(mc));
  r["ipmb_event_reciever_support"] =
      INTEGER(ipmi_mc_ipmb_event_receiver_support(mc));
  r["fru_inventory_support"] = INTEGER(ipmi_mc_fru_inventory_support(mc));
  r["sel_device_support"] = INTEGER(ipmi_mc_sel_device_support(mc));
  r["sdr_respository_support"] = INTEGER(ipmi_mc_sdr_repository_support(mc));
  r["sensor_device_support"] = INTEGER(ipmi_mc_sensor_device_support(mc));
  r["is_active"] = INTEGER(ipmi_mc_is_active(mc));

  unsigned char guid = 0;
  auto rv = ipmi_mc_get_guid(mc, &guid);
  switch (rv) {
  case ENOSYS:
    r["guid"] = "not available";
    break;

  case NOERR:
    r["guid"] = std::string(reinterpret_cast<const char*>(&guid), 16);
    break;

  default:
    LOG(ERROR) << "Unexpected error retrieving MC GUID: " << strerror(rv);
  }

  auto c = reinterpret_cast<IPMIClient*>(data);
  c->insertRowsQueue(r["name"] + "-" + r["id"], r);
}

IPMIClient& IPMIClient::get() {
  static IPMIClient c;
  return c;
}

bool IPMIClient::isUp() {
  return up_.load();
}

IPMIClient::~IPMIClient() {
  up_.store(false);
}

IPMIClient::IPMIClient()
    : InternalRunnable("ipmi_client"),
      up_(false),
      domain_(nullptr),
      os_hnd_(nullptr, kFreeOSHandle),
      lanCh_(0) {
  TLOG << "First time initialization of OpenIPMI client.  This could "
          "take a few minutes";

  std::unique_ptr<os_handler_t, std::function<void(os_handler_t*&)>> tempHandle(
      ipmi_posix_setup_os_handler(), kFreeOSHandle);
  if (tempHandle.get() == nullptr) {
    LOG(ERROR) << "Could not allocate posix handler with ipmi_smi_setup_con";
    return;
  }
  os_hnd_.swap(tempHandle);

  TLOG << "Setting OpenIPMI log handler";
  os_hnd_.get()->set_log_handler(os_hnd_.get(), ipmiLoggerCB);

  TLOG << "Initializing OpenIPMI client";
  auto rv = ipmi_init(os_hnd_.get());
  if (rv != 0) {
    LOG(ERROR) << "IPMI initialization failed: " << strerror(rv);
    return;
  }

  TLOG << "Setting up OpenIPMI connection";
  // Only support 1 IPMI connection for now..
  rv = ipmi_smi_setup_con(0, os_hnd_.get(), NULL, &con_);
  if (rv != 0) {
    LOG(WARNING) << "Error setting up SMI connection: " << strerror(rv);
    return;
  }

  TLOG << "Opening IPMI domain";
  rv = ipmi_open_domain(
      "", &con_, 1, NULL, NULL, IPMIFullyUpCB, this, NULL, 0, NULL);
  if (rv != 0) {
    LOG(ERROR) << "Error opening IPMI domain: " << strerror(rv);
    return;
  }

  TLOG << "Adding IPMIClient as a dispatcher service";
  Dispatcher::addService(
      std::shared_ptr<IPMIClient>(this, [](IPMIClient* c) { c->stop(); }));

  auto timeout = getTimeoutConfig("timeout", IPMI_DEFAULT_INIT_TIMEOUT);

  TLOG << "Waiting for OpenIPMI to reach 'fully up' state to retrieve "
          "domain (may take up to "
       << timeout << " ms)";
  blkAndOp([this] { return domain_ != nullptr; }, timeout);

  if (domain_ != nullptr) {
    up_.store(true);
  } else {
    LOG(WARNING) << "IPMI BMC was not responsive";
    return;
  }

  TLOG << "Searching for IPMI channel for LAN communication";
  findLANCh();

  TLOG << "Setting up ipmi_lanparm_t for system MCs";
  rv = ipmi_domain_iterate_mcs(
      domain_,
      [](ipmi_domain_t* domain, ipmi_mc_t* mc, void* data) {
        auto c = reinterpret_cast<IPMIClient*>(data);
        c->addLANParm(getMCKey(mc), mc);
      },
      this);
  if (rv != 0) {
    LOG(ERROR) << "Could not register ipmi_domain_iterate_mcs: "
               << strerror(rv);
  }

  blkAndOp([]() { return false; }, 1000);

  TLOG << "IPMIClient initialization complete";
}

ipmi_lanparm_t* IPMIClient::getLANParm(const std::string& name, ipmi_mc_t* mc) {
  if (lanparms_.find(name) != lanparms_.end()) {
    return lanparms_[name].get();
  }

  if (addLANParm(name, mc)) {
    return lanparms_[name].get();
  }

  return nullptr;
}

bool IPMIClient::addLANParm(const std::string& name, ipmi_mc_t* mc) {
  ipmi_lanparm_t* lp = nullptr;

  auto rv = ipmi_lanparm_alloc(mc, lanCh_, &lp);
  if (rv != 0) {
    LOG(ERROR) << "Could not allocate ipmi_lanparm_alloc for local BMC: "
               << strerror(rv);
    return false;
  }

  if (lp == nullptr) {
    LOG(ERROR) << "Could not successfully allocation "
                  "ipmi_lanparm_t*: still a nullptr";
    return false;
  }

  ipmi_lanparm_ref(lp);

  lanparms_[getMCKey(mc)] =
      std::unique_ptr<ipmi_lanparm_t, std::function<void(ipmi_lanparm_t*)>>(
          lp, kFreeLANParm);
  return true;
}

void IPMIClient::insertRowsQueue(const std::string& key,
                                 const std::string& columnName,
                                 const std::string& columnValue) {
  rowsQueue_[key][columnName] = columnValue;
}

void IPMIClient::insertRowsQueue(const std::string& key, const Row& row) {
  rowsQueue_[key] = row;
}

void IPMIClient::toQueryData(QueryData& results) {
  for (const auto& mcData : rowsQueue_) {
    results.push_back(mcData.second);
  }
}

void IPMIClient::pushParmData(parmData* parm) {
  WriteLock lock(parmMutex_);
  parmsOnHeap_.push_back(parm);
}

void IPMIClient::rmParmData(parmData* parm) {
  WriteLock lock(parmMutex_);
  // Check if parm exists first.
  auto i = std::find(parmsOnHeap_.begin(), parmsOnHeap_.end(), parm);
  if (i == parmsOnHeap_.end()) {
    return;
  }

  std::unique_ptr<parmData, std::function<void(parmData*)>> _(
      parm, [&](parmData* p) {
        delete p;
        parmsOnHeap_.erase(i);
      });
}

void IPMIClient::blkAndOp(std::function<bool()> ready, int timeoutDurMS) {
  const size_t pauseDuration = 5;
  // To account for timing skews.
  const size_t adjustedPauseDuration = 6;

  std::atomic<bool> done(false);
  auto fut = std::async(std::launch::async, [&, this] {
    while (timeoutDurMS > 0 && !done.load()) {
      pauseMilli(pauseDuration);
      if (interrupted()) {
        LOG(WARNING) << "EXITING!!!!!!!!!!\n\n";
        return;
      }
      // TLOG << "T1: JUST POSTED FOR 5 MS";
      timeoutDurMS -= adjustedPauseDuration;

      TLOG << "CURRENT TIMEOUT IS " << timeoutDurMS;
    }
  });
  std::future_status status;

  do {
    auto rv = oneOp();
    if (rv == EINTR || rv == EINVAL) {
      done.store(true);
      return;
    }
    if (rv != 0) {
      LOG(ERROR) << "Could not handle IPMI event: " << strerror(rv);
    }

    status = fut.wait_for(std::chrono::milliseconds(1));
    TLOG << "T2: JUST WAITED FOR 1 MS; STATUS IS ";

    if (status == std::future_status::ready) {
      TLOG << "STATUS IS READY!!!!!\n\n";
    } else {
      TLOG << "Status is not ready\n\n";
    }

  } while (status != std::future_status::ready && !ready());
  std::cout << "EXITINGGGGGGGG\n\n";
  done.store(true);
}

void IPMIClient::setLANCh(unsigned int ch) {
  lanCh_ = ch;
}

void IPMIClient::findLANCh() {
  iterateMCs([](ipmi_domain_t* domain, ipmi_mc_t* mc, void* data) {
    for (unsigned int i = 0; i < 16; i++) {
      auto rv = ipmi_mc_channel_get_info(
          mc,
          i,
          [](ipmi_mc_t* mc, int err, ipmi_channel_info_t* info, void* data) {
            if (err != 0) {
              TLOG << "Unexpected error on ipmi_mc_channel_get_info "
                      "callback: "
                   << strerror(err);
              return;
            }

            unsigned int ch;
            auto rv = ipmi_channel_info_get_channel(info, &ch);
            if (rv != 0) {
              LOG(ERROR) << "Could not get channel: " << strerror(rv);
              return;
            }

            unsigned int medium;
            rv = ipmi_channel_info_get_medium(info, &medium);
            if (rv != 0) {
              LOG(ERROR) << "Could not get medium info for channel "
                         << std::to_string(ch) << ": " << strerror(rv);
              return;
            }

            if (medium == IPMI_CHANNEL_MEDIUM_8023_LAN) {
              auto c = reinterpret_cast<IPMIClient*>(data);
              c->setLANCh(ch);
            }

          },
          data);
      if (rv != 0) {
        LOG(ERROR) << "Could not get channel info for channel "
                   << std::to_string(i) << ": " << strerror(rv);
      }
    }
  });
  blkAndOp([]() { return false; }, 500);
}

int IPMIClient::oneOp() {
  struct timeval tv = {0, 500000};
  TLOG << "BOOM@@@@!!!!\n\n";
  return os_hnd_.get()->perform_one_op(os_hnd_.get(), &tv);
}

void IPMIClient::setDomain(ipmi_domain_t* d) {
  domain_ = d;
}

void IPMIClient::iterateEntities(ipmi_entities_iterate_entity_cb cb) {
  if (domain_ == nullptr) {
    LOG(ERROR) << "No IPMI domain pointer..nothing to do";
    return;
  }

  auto rv = ipmi_domain_iterate_entities(domain_, cb, this);
  if (rv != 0) {
    LOG(ERROR) << "Could not register callback for "
                  "ipmi_domain_iterate_entities: "
               << strerror(rv);
    return;
  }
}

void IPMIClient::iterateMCs(ipmi_domain_iterate_mcs_cb cb) {
  if (domain_ == nullptr) {
    LOG(ERROR) << "No IPMI domain pointer..nothing to do";
    return;
  }

  auto rv = ipmi_domain_iterate_mcs(domain_, cb, this);
  if (rv != 0) {
    LOG(ERROR) << "Could not register callback for ipmi_domain_iterate_mcs: "
               << strerror(rv);
    return;
  }
}

void IPMIClient::getLANConfigs(QueryData& results) {
  WriteLock lock(busy_);
  rowsQueue_.clear();

  iterateMCs(getLANsCB);

  auto timeout = getTimeoutConfig("lan_query_timeout", IPMI_QUERY_LAN_TIMEOUT);
  blkAndOp([]() { return false; }, timeout);

  toQueryData(results);

  rowsQueue_.clear();
}

void IPMIClient::getThresholdSensors(QueryData& results) {
  WriteLock lock(busy_);
  rowsQueue_.clear();

  iterateEntities(getThresholdSensorCB);

  auto timeout = getTimeoutConfig("threshold_sensors_query_timeout",
                                  IPMI_QUERY_THRESHOLD_SENSORS_TIMEOUT);
  blkAndOp([]() { return false; }, timeout);

  toQueryData(results);

  rowsQueue_.clear();
}

void IPMIClient::getFRUs(QueryData& results) {
  WriteLock lock(busy_);
  rowsQueue_.clear();

  iterateEntities(getFRUCB);

  auto timeout = getTimeoutConfig("fru_query_timeout", IPMI_QUERY_FRU_TIMEOUT);
  blkAndOp([]() { return false; }, timeout);

  toQueryData(results);

  rowsQueue_.clear();
}

void IPMIClient::getMCs(QueryData& results) {
  WriteLock lock(busy_);
  rowsQueue_.clear();

  iterateMCs(iterateMCsCB);

  auto timeout = getTimeoutConfig("mc_query_timeout", IPMI_QUERY_MC_TIMEOUT);
  blkAndOp([]() { return false; }, timeout);

  toQueryData(results);

  rowsQueue_.clear();
}

void IPMIClient::start() {
  while (!interrupted()) {
    pauseMilli(IPMI_CLEANUP_DURATION);
    if (interrupted()) {
      return;
    }

    if (isUp()) {
      TLOG << "Running IPMIClient cleanup routine";
      cleanup();
    }
  }
}

void IPMIClient::stop() {
  if (up_.load()) {
    up_.store(false);
  }

  cleanup();
}

void IPMIClient::cleanup() {
  WriteLock lock(busy_);
  if (!rowsQueue_.empty()) {
    TLOG << "IPMIClient cleaning up rowsQueue_ since it's not empty";
    rowsQueue_.clear();
  }
}
}
