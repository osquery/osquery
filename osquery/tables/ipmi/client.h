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

#include <map>
#include <string>
#include <vector>

#include <OpenIPMI/ipmi_lanparm.h>
#include <OpenIPMI/ipmiif.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/tables.h>

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

///  parmData encapsulates things that are required for retrieving LANPARM
struct parmData;

/**
 * @brief Client for interacting with OpenIPMI
 *
 * IPMIClient is a singleton object accessible only by the IPMIClient::get
 * static method.  IPMIClient is lazily loaded on the first query to any IPMI
 * table.  The initialization process waits for OpenIPMI to be in the "fully
 * up" state so it can a few minutes.
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
  void insertRowsQueue(const std::string& key,
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
   * nature of IPMI and the fact that there's no guarantee when/if the
   * requested data ever returns.
   */
  Mutex busy_;

  /* @brief Mutex for handling parmData*
   *
   * IPMI does not guarantee when an resp will be received.  Therefore we
   * can't know when the callback for retrieving a LANParm will be called.
   * Because of this nature, we need a mutex specifically for handling the
   * deletion of parmData to avoid a potential double free error.
   */
  Mutex parmMutex_;

  /// IPMI domain kept by the client.
  ipmi_domain_t* domain_;

  /// IPMI connection struct kept by the client.
  ipmi_con_t* con_;

  /// map of ipmi_lanparm_t* kept by the client for querying IPMI LANPARM
  /// stuff.
  std::map<
      std::string,
      std::unique_ptr<ipmi_lanparm_t, std::function<void(ipmi_lanparm_t*)>>>
      lanparms_;

  /// Non-threaded OS handler for OpenIPMI.
  std::unique_ptr<os_handler_t, std::function<void(os_handler_t*&)>> os_hnd_;

  /// IPMI channel for getting LAN information.
  unsigned int lanCh_;
};

} // namespace osquery
