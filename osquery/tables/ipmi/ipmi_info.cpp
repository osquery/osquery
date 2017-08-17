/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
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

namespace osquery {

// Callbacks for OpenIPMI
extern "C" {
void getLANsCB(ipmi_domain_t* domain, ipmi_mc_t* mc, void* data);
void readThresholdSensorCB(ipmi_sensor_t* sensor,
                           int err,
                           enum ipmi_value_present_e value_present,
                           unsigned int raw_value,
                           double val,
                           ipmi_states_t* states,
                           void* data);
void getFRUCB(ipmi_entity_t* entity, void* data);
void iterateMCsCB(ipmi_domain_t* domain, ipmi_mc_t* mc, void* data);
void IPMIFullyUpCB(ipmi_domain_t* domain, void* data);
void ipmiLoggerCB(os_handler_t* handler,
                  const char* format,
                  enum ipmi_log_type_e logType,
                  va_list ap);
}

/// Unique pointer deleter for os_handler_t*
const auto kFreeOSHandle = [](os_handler_t* h) {
  if (h != nullptr) {
    ipmi_posix_free_os_handler(h);
  }
};

/// Unique pointer deleter for ipmi_lanparm_t*
const auto kFreeLANParm = [](ipmi_lanparm_t* lp) {
  int rv = ipmi_lanparm_destroy(lp, NULL, NULL);
  if (rv != 0) {
    LOG(WARNING) << "Did not successfully destroy ipmi_lanparm_t*: "
                 << strerror(rv);
  }
};

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
  char name[IPMI_MC_NAME_LEN];
  int len = ipmi_mc_get_name(mc, name, IPMI_MC_NAME_LEN);
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

class IPMIClient;

/**
 * @brief parmData encapsulates things that are required for retrieving LANPARM
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

/**
 * @brief Client for interacting with OpenIPMI
 *
 * IPMIClient is a singleton object accessible only by the IPMIClient::get
 * static method.  IPMIClient is lazily loaded on the first query to any IPMI
 * table.  The initialization process waits for OpenIPMI to be in the "fully up"
 * state so it can a few minutes.
 */
class IPMIClient : public InternalRunnable {
 public:
  /**
   * @brief retrieves instance of IPMIClient (singleton).
   */
  static IPMIClient& get();

 public:
  /**
   * @brief retrieves QueryData for ipmi_threshold_sensors.
   *
   * @param results Reference to QueryData.
   */
  void getThresholdSensors(QueryData& results);

  /**
   * @brief retrieves QueryData for ipmi_lan.
   *
   * @param results Reference to QueryData.
   */
  void getLANConfigs(QueryData& results);

  /**
   * @brief retrieves QueryData for ipmi_fru.
   *
   * @param results Reference to QueryData.
   */
  void getFRUs(QueryData& results);

  /**
   * @brief retrieves QueryData for ipmi_mc.
   *
   * @param results Reference to QueryData.
   */
  void getMCs(QueryData& results);

  /**
   * @brief checks if IPMIClient is successfully initiated.
   *
   * @return bool indicating client state.
   */
  bool isUp();

  /// Starts background clean up routine.  Implements InternalRunnable.
  void start() override;

  /// Sets running state to false and does one final clean up.
  void stop() override;

  ~IPMIClient();
  IPMIClient(IPMIClient const& client) = delete;
  void operator=(IPMIClient const& client) = delete;

 private:
  IPMIClient();

  /// Sets domain of client instance.
  void setDomain(ipmi_domain_t* d);

  /// Sets the local IPMI LAN channel.
  void setLANCh(unsigned int ch);

  /// Gets a ipmi_lanparm_t* by key name from the instance.
  ipmi_lanparm_t* getLANParm(const std::string& name, ipmi_mc_t* mc);

  /// Add a ipmi_lanparm_t* by key name to the instance.
  bool addLANParm(const std::string& name, ipmi_mc_t* mc);

  /// Insert a column pair to the Row at key.
  void insertRowsQueue(std::string key,
                       const std::string& columnName,
                       const std::string& columnValue);

  /// Insert a new Row for the key.
  void insertRowsQueue(const std::string& key, const Row& row);

  /// Push a new parmData* to instance property parmsOnHeap_.
  void pushParmData(parmData* parm);

  /// Removes parmData* from parmsOnHeap_ and calls delete on it.
  void rmParmData(parmData* parm);

  /// Performs one operation to get an IPMI event.  Times out after 500ms.
  int oneOp();

  /// Blocks for duration specified by timeoutDurMS or termination function
  /// returns true performing oneOp.
  void blkAndOp(std::function<bool()> termF, int timeoutDurMS = 500);

  /// Searches all IPMI channels for 802.3 LAN channel; uses first found.
  void findLANCh();

  /// Converts instance local rowsQueue_ to QueryData.
  void toQueryData(QueryData& results);

  /// Iterate all IPMI entities by registering cb.
  void iterateEntities(ipmi_entities_iterate_entity_cb cb);

  /// Iterate all IPMI mcs by registering cb.
  void iterateMCs(ipmi_domain_iterate_mcs_cb);

  /// Background loop for cleaning data from late IPMI events.
  void cleanup();

  /// OpenIPMI callback for retrieving BMC LAN info.
  friend void getLANsCB(ipmi_domain_t* domain, ipmi_mc_t* mc, void* data);

  /// OpenIPMI callback for reading threshold sensor info.
  friend void readThresholdSensorCB(ipmi_sensor_t* sensor,
                                    int err,
                                    enum ipmi_value_present_e value_present,
                                    unsigned int raw_value,
                                    double val,
                                    ipmi_states_t* states,
                                    void* data);

  /// OpenIPMI callback for retrieving FRU info.
  friend void getFRUCB(ipmi_entity_t* entity, void* data);

  /// OpenIPMI callback for iterating over system MCs.
  friend void iterateMCsCB(ipmi_domain_t* domain, ipmi_mc_t* mc, void* data);

  /// OpenIPMI callback for work when the OpenIPMI reaches "fully up" state.
  friend void IPMIFullyUpCB(ipmi_domain_t* domain, void* data);

  /// Other functions that need access to private functionality.
  friend void getPARM(ipmi_lanparm_t* lp,
                      unsigned int parm,
                      const std::string& key,
                      const std::string& colName,
                      IPMIClient* client);

  /// Client managed Rows for public queries.
  std::map<std::string, Row> rowsQueue_;

  /// Client managed parmData* that live on heap.  Due to the nature of IPMI,
  /// this is probably the safest way to manage it.
  std::vector<parmData*> parmsOnHeap_;

  /// Stores state of client.
  std::atomic<bool> up_;

  /* @brief Mutex to check if client is busy with a query.
   *
   * This is so bg task can clean up memory.  This is due to the asynchronous
   * nature of IPMI and the fact that there's no guarantee when/if the requested
   * data ever returns.
   */
  Mutex busy_;

  /* @brief Mutex for handling parmData*
   *
   * IPMI does not guarantee when an resp will be received.  Therefore we can't
   * know when the callback for retrieving a LANParm will be called.  Because of
   * this nature, we need a mutex specifically for handling the deletion of
   * parmData to avoid a potential double free error.
   */
  Mutex parmMutex_;

  /// IPMI domain kept by the client.
  ipmi_domain_t* domain_;

  /// IPMI connection struct kept by the client.
  ipmi_con_t* con_;

  /// map of ipmi_lanparm_t* kept by the client for querying IPMI LANPARM stuff.
  std::map<
      std::string,
      std::unique_ptr<ipmi_lanparm_t, std::function<void(ipmi_lanparm_t*)>>>
      lanparms_;

  /// Non-threaded OS handler for OpenIPMI.
  std::unique_ptr<os_handler_t, std::function<void(os_handler_t*&)>> os_hnd_;

  /// IPMI channel for getting LAN information.
  unsigned int lanCh_;
};

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
    /* We use C style data structures and string functions because we are given
     * C style formatters and variadic functions */
    const size_t max = 1024;
    char buf[max];
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
    LOG(WARNING)
        << "Expected data length of 2 for IPMI_LANPARM_IP_ADDRESS_SRC, but got "
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
  int rv =
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

  int rv = ipmi_lanparm_get_parm(
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
  int len = ipmi_mc_get_name(mc, name, IPMI_MC_NAME_LEN);
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
  IPMIClient* c = reinterpret_cast<IPMIClient*>(data);
  c->setDomain(domain);

  return;
}

/// Gets the the value suffix for a sensor reading.
std::string getSensorThresholdSuffix(ipmi_sensor_t* sensor) {
  std::string percent, base, mod_use, modifier, rate;

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

  rate = ipmi_sensor_get_rate_unit_string(sensor);

  return percent + " " + base + mod_use + modifier + rate;
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

  ipmi_mc_t* mc = ipmi_sensor_get_mc(sensor);
  r["mc_name"] = getMCName(mc, "unknown");
  r["mc_id"] = INTEGER(ipmi_mc_device_id(mc));

  const int maxChar = 256;
  char name[maxChar];
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

  IPMIClient* c = reinterpret_cast<IPMIClient*>(data);
  c->insertRowsQueue(r["name"] + "-" + r["mc_name"] + "-" + r["mc_id"], r);
}

void getThresholdSensorCB(ipmi_entity_t* entity, void* data) {
  ipmi_entity_iterate_sensors(
      entity,
      [](ipmi_entity_t* ent, ipmi_sensor_t* sensor, void* data) {
        if (ipmi_sensor_get_event_reading_type(sensor) ==
            IPMI_EVENT_READING_TYPE_THRESHOLD) {
          int rv = ipmi_sensor_get_reading(sensor, readThresholdSensorCB, data);
          if (rv != 0) {
            LOG(ERROR) << "Could not get sensor reading: " << strerror(rv);
          }
        }
      },
      data);
}

/// Walks FRU nodes and appends to Row.
void traverseFRUNodeTree(ipmi_fru_node_t* node, Row& row) {
  time_t tm;
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
    int rv = ipmi_fru_node_get_field(node,
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
      row[colName] = INTEGER(intval);
      break;

    case IPMI_FRU_DATA_TIME:
      row[colName] = BIGINT(tm);
      break;

    case IPMI_FRU_DATA_ASCII:
      row[colName] = data;
      break;

    case IPMI_FRU_DATA_BOOLEAN:
      row[colName] = INTEGER(intval);
      break;

    case IPMI_FRU_DATA_FLOAT:
      row[colName] = std::to_string(floatval);
      break;

    case IPMI_FRU_DATA_SUB_NODE:
      traverseFRUNodeTree(subnode, row);
      break;

    default:
      // we don't want any of the other data
      break;
    }
  }
}

void getFRUCB(ipmi_entity_t* entity, void* data) {
  ipmi_fru_t* fru = ipmi_entity_get_fru(entity);
  if (fru == nullptr) {
    return;
  }

  std::unique_ptr<ipmi_fru_t, std::function<void(ipmi_fru_t*)>> freeFru(
      fru, [](ipmi_fru_t* f) {
        int rv = ipmi_fru_destroy(f, NULL, NULL);
        if (rv != 0) {
          TLOG << "Could not register ipmi_fru_destroy: " << strerror(rv);
          return;
        }

      });

  Row r;
  r["entity_id"] = INTEGER(ipmi_entity_get_entity_id(entity));
  r["entity_instance"] = INTEGER(ipmi_entity_get_entity_instance(entity));

  char name[IPMI_FRU_NAME_LEN];
  int len = ipmi_fru_get_name(fru, name, IPMI_FRU_NAME_LEN);
  if (len < 1) {
    r["name"] = "unknown";
  } else {
    r["name"] = name;
  }

  ipmi_fru_node_t* node = nullptr;

  const char* type = "";
  int rv = ipmi_fru_get_root_node(fru, &type, &node);
  if (rv != 0) {
    TLOG << "Could not get FRU root node: " << strerror(rv);
    return;
  }

  r["type"] = type;
  traverseFRUNodeTree(node, r);

  IPMIClient* c = reinterpret_cast<IPMIClient*>(data);
  c->insertRowsQueue(
      r["entity_id"] + "-" + r["entity_instance"] + "-" + r["name"], r);
}

void iterateMCsCB(ipmi_domain_t* domain, ipmi_mc_t* mc, void* data) {
  Row r;

  char name[IPMI_MC_NAME_LEN];
  int len = ipmi_mc_get_name(mc, name, IPMI_MC_NAME_LEN);
  if (len > 0) {
    r["name"] = name;
  }

  r["device_id"] = INTEGER(ipmi_mc_device_id(mc));
  r["device_revision"] = INTEGER(ipmi_mc_device_revision(mc));
  r["device_available"] = INTEGER(ipmi_mc_device_available(mc));
  r["firmware_major_version"] = INTEGER(ipmi_mc_major_fw_revision(mc));
  r["firmware_minor_version"] = INTEGER(ipmi_mc_minor_fw_revision(mc));
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
  int rv = ipmi_mc_get_guid(mc, &guid);
  switch (rv) {
  case ENOSYS:
    r["guid"] = "not available";
    break;

  case 0:
    r["guid"] = std::string(reinterpret_cast<const char*>(&guid), 16);
    break;

  default:
    LOG(ERROR) << "Unexpected error retrieving MC GUID: " << strerror(rv);
  }

  IPMIClient* c = reinterpret_cast<IPMIClient*>(data);
  c->insertRowsQueue(r["name"] + "-" + r["device_id"], r);
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
    : up_(false), domain_(nullptr), os_hnd_(nullptr, kFreeOSHandle), lanCh_(0) {
  LOG(WARNING) << "First time initialization of OpenIPMI client.  This could "
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
  int rv = ipmi_init(os_hnd_.get());
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
  if (ipmi_open_domain(
          "", &con_, 1, NULL, NULL, IPMIFullyUpCB, this, NULL, 0, NULL) != 0) {
    LOG(ERROR) << "Error opening IPMI domain: " << strerror(rv);
    return;
  }

  TLOG << "Adding IPMIClient as a dispatcher service";
  Dispatcher::addService(
      std::shared_ptr<IPMIClient>(this, [](IPMIClient* c) { c->stop(); }));

  // Set default timeout value.
  size_t timeout = 360000;
  auto parser = Config::getParser("ipmi");
  if (parser != nullptr && parser.get() != nullptr) {
    const auto& config = parser->getData().get_child(
        kIPMIConfigParserRootKey, boost::property_tree::ptree("UNEXPECTED"));
    if (config.get_value("") == "UNEXPECTED") {
      LOG(WARNING) << "Could not load ipmi configuration root key: "
                   << kIPMIConfigParserRootKey;
    }

    timeout = config.get_child("timeout", boost::property_tree::ptree())
                  .get_value<size_t>(360000);
  }

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
        IPMIClient* c = reinterpret_cast<IPMIClient*>(data);
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

  int rv = ipmi_lanparm_alloc(mc, lanCh_, &lp);
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

  lanparms_[getMCKey(mc)] =
      std::unique_ptr<ipmi_lanparm_t, std::function<void(ipmi_lanparm_t*)>>(
          lp, kFreeLANParm);
  return true;
}

void IPMIClient::insertRowsQueue(std::string key,
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
  std::atomic<bool> done(false);

  auto fut = std::async(std::launch::async, [&, this] {
    while (timeoutDurMS > 0 && !done.load()) {
      pauseMilli(5);
      if (interrupted()) {
        return;
      }

      timeoutDurMS -= 6;
    }
  });
  std::future_status status;

  do {
    int rv = oneOp();
    if (rv == EINTR) {
      done.store(true);
      return;
    }
    if (rv != 0) {
      LOG(ERROR) << "Could not handle IPMI event: " << strerror(rv);
    }

    status = fut.wait_for(std::chrono::milliseconds(1));

  } while (status != std::future_status::ready && !ready());

  done.store(true);
}

void IPMIClient::setLANCh(unsigned int ch) {
  lanCh_ = ch;
}

void IPMIClient::findLANCh() {
  iterateMCs([](ipmi_domain_t* domain, ipmi_mc_t* mc, void* data) {
    for (unsigned int i = 0; i < 16; i++) {
      int rv = ipmi_mc_channel_get_info(
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
            int rv = ipmi_channel_info_get_channel(info, &ch);
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
              IPMIClient* c = reinterpret_cast<IPMIClient*>(data);
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
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 500000;

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

  int rv = ipmi_domain_iterate_entities(domain_, cb, this);
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

  int rv = ipmi_domain_iterate_mcs(domain_, cb, this);
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
  blkAndOp([]() { return false; }, 500);
  toQueryData(results);

  rowsQueue_.clear();
}

void IPMIClient::getThresholdSensors(QueryData& results) {
  WriteLock lock(busy_);
  rowsQueue_.clear();

  iterateEntities(getThresholdSensorCB);
  blkAndOp([]() { return false; }, 500);
  toQueryData(results);

  rowsQueue_.clear();
}

void IPMIClient::getFRUs(QueryData& results) {
  WriteLock lock(busy_);
  rowsQueue_.clear();

  iterateEntities(getFRUCB);

  blkAndOp([]() { return false; }, 100);
  toQueryData(results);

  rowsQueue_.clear();
}

void IPMIClient::getMCs(QueryData& results) {
  WriteLock lock(busy_);
  rowsQueue_.clear();

  iterateMCs(iterateMCsCB);

  blkAndOp([]() { return false; }, 100);
  toQueryData(results);

  rowsQueue_.clear();
}

void IPMIClient::start() {
  while (!interrupted()) {
    pauseMilli(120000);
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

namespace tables {

QueryData genIPMILANs(QueryContext& context) {
  QueryData results;

  IPMIClient& c = IPMIClient::get();
  if (!c.isUp()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.getLANConfigs(results);

  return results;
}

QueryData genIPMIThresholdSensors(QueryContext& context) {
  QueryData results;

  IPMIClient& c = IPMIClient::get();
  if (!c.isUp()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.getThresholdSensors(results);

  return results;
}

QueryData genIPMIFRUs(QueryContext& context) {
  QueryData results;

  IPMIClient& c = IPMIClient::get();
  if (!c.isUp()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.getFRUs(results);

  return results;
}

QueryData genIPMIMCs(QueryContext& context) {
  QueryData results;
  IPMIClient& c = IPMIClient::get();
  if (!c.isUp()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.getMCs(results);

  return results;
}

} // namespace tables
} // namespace osquery
