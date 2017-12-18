/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include <lldp-const.h>
#include <lldpctl.h>

namespace osquery {
namespace tables {

// Deleter to be used with unique_ptr wrap on lldp_atom_t pointers.
auto delLLDPAtom = [](lldpctl_atom_t* a) { lldpctl_atom_dec_ref(a); };

/* kNoAtomStrDefault is the default value used when lldp_atom_get_str does not
 * return a valid string value. */
const std::string kNoAtomStrDefault = "unknown";

struct ChassisCapability {
  bool available;
  bool enabled;
};

inline std::string getAtomStr(lldpctl_atom_t* atom, lldpctl_key_t key) {
  if (atom == nullptr) {
    return kNoAtomStrDefault;
  }

  const char* val = lldpctl_atom_get_str(atom, key);
  if (val == nullptr) {
    return kNoAtomStrDefault;
  }

  return val;
}

inline std::string commaDelimitedStr(lldpctl_atom_t* things,
                                     lldpctl_key_t key) {
  if (things == nullptr) {
    return "";
  }

  std::string result;
  lldpctl_atom_t* each = nullptr;

  lldpctl_atom_foreach(things, each) {
    result = result + getAtomStr(each, key) + ",";
  }
  // Remove trailing comma.
  if (!result.empty()) {
    result.pop_back();
  }

  return result;
}

class LLDPNeighbor {
 public:
  /**
   * @brief LLDPNeighbor is responsible for retrieving LLDP information on one
   * neighbor.  On construction, a Row is initialized for member functions to
   * fill.
   *
   * It does not handle the the reference decrementing of the chassis and port
   * parameter.  That responsibility is on the caller.
   *
   * @param port liblldpctl atom type of given port
   * @param chassis liblldpctl atom type of given chassis
   *
   */
  LLDPNeighbor(lldpctl_atom_t* port, lldpctl_atom_t* chassis)
      : port_(port), chassis_(chassis) {}

  LLDPNeighbor(const LLDPNeighbor& ln) = delete;

  Row& getNeighbor();

 private:
  lldpctl_atom_t* port_;
  lldpctl_atom_t* chassis_;
  Row row_;

  void getChassis();
  void getChasisCapability(u_int8_t mask,
                           std::string const& availCol,
                           std::string const& enabledCol);
  void getPort();
  void getPMDAutoNeg(long int autonegAdversised,
                     long int hdMask,
                     long int fdMask,
                     std::string const& hdCol,
                     std::string const& fdCol);
  void getVLAN();
  void getMED();
  void getMEDCap();
  void getPIDs();
  void getPPVIDs();
};

inline void LLDPNeighbor::getChasisCapability(u_int8_t mask,
                                              std::string const& availCol,
                                              std::string const& enabledCol) {
  if (lldpctl_atom_get_int(chassis_, lldpctl_k_chassis_cap_available) & mask) {
    row_[availCol] = "1";
    row_[enabledCol] =
        (lldpctl_atom_get_int(chassis_, lldpctl_k_chassis_cap_enabled) & mask)
            ? "1"
            : "0";
  }
}

inline void LLDPNeighbor::getPMDAutoNeg(long int autonegAdversised,
                                        long int hdMask,
                                        long int fdMask,
                                        std::string const& hdCol,
                                        std::string const& fdCol) {
  row_[hdCol] = ((autonegAdversised & hdMask) ? "1" : "0");
  row_[fdCol] = ((autonegAdversised & fdMask) ? "1" : "0");
}

void LLDPNeighbor::getPIDs() {
  std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> pids(
      lldpctl_atom_get(port_, lldpctl_k_port_pis), delLLDPAtom);
  row_["pids"] = commaDelimitedStr(pids.get(), lldpctl_k_pi_id);
}

void LLDPNeighbor::getPPVIDs() {
  std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> ppvids(
      lldpctl_atom_get(port_, lldpctl_k_port_ppvids), delLLDPAtom);
  if (ppvids.get() == nullptr) {
    return;
  }

  std::string supported;
  std::string enabled;

  lldpctl_atom_t* ppvid = nullptr;
  lldpctl_atom_foreach(ppvids.get(), ppvid) {
    long int status = lldpctl_atom_get_int(ppvid, lldpctl_k_ppvid_status);
    long int id = lldpctl_atom_get_int(ppvid, lldpctl_k_ppvid_id);

    if (status > 0 && id > 0) {
      std::string name = getAtomStr(ppvid, lldpctl_k_ppvid_id);

      if (status & LLDP_PPVID_CAP_SUPPORTED) {
        supported = supported + name + ",";
      }

      if (status & LLDP_PPVID_CAP_ENABLED) {
        enabled = enabled + name + ",";
      }
    }
  }

  if (supported.size() > 0) {
    supported.pop_back();
  }
  row_["ppvids_supported"] = supported;

  if (enabled.size() > 0) {
    enabled.pop_back();
  }
  row_["ppvids_enabled"] = enabled;
}

void LLDPNeighbor::getMEDCap() {
  long int availableCap =
      lldpctl_atom_get_int(chassis_, lldpctl_k_chassis_med_cap);
  if (availableCap < 0) {
    return;
  }

  row_["med_capability_capabilities"] =
      (availableCap & LLDP_MED_CAP_CAP) ? "1" : "0";
  row_["med_capability_policy"] =
      (availableCap & LLDP_MED_CAP_POLICY) ? "1" : "0";
  row_["med_capability_location"] =
      (availableCap & LLDP_MED_CAP_LOCATION) ? "1" : "0";
  row_["med_capability_mdi_pse"] =
      (availableCap & LLDP_MED_CAP_MDI_PSE) ? "1" : "0";
  row_["med_capability_mdi_pd"] =
      (availableCap & LLDP_MED_CAP_MDI_PD) ? "1" : "0";
  row_["med_capability_inventory"] =
      (availableCap & LLDP_MED_CAP_IV) ? "1" : "0";
}

void LLDPNeighbor::getMED() {
  if (lldpctl_atom_get_int(chassis_, lldpctl_k_chassis_med_type) <= 0) {
    return;
  }

  row_["med_device_type"] = getAtomStr(chassis_, lldpctl_k_chassis_med_type);
  // Capabilities status
  getMEDCap();

  // Policy Capabilities
  std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> policies(
      lldpctl_atom_get(port_, lldpctl_k_port_med_policies), delLLDPAtom);
  row_["med_policies"] =
      commaDelimitedStr(policies.get(), lldpctl_k_med_policy_type);
}

void LLDPNeighbor::getVLAN() {
  row_["pvid"] = getAtomStr(port_, lldpctl_k_port_vlan_pvid);

  std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> vlans(
      lldpctl_atom_get(port_, lldpctl_k_port_vlans), delLLDPAtom);

  row_["vlans"] = commaDelimitedStr(vlans.get(), lldpctl_k_vlan_id);
}

void LLDPNeighbor::getPort() {
  row_["port_id"] = getAtomStr(port_, lldpctl_k_port_id);
  row_["port_id_type"] = getAtomStr(port_, lldpctl_k_port_id_subtype);
  row_["port_aggregation_id"] = getAtomStr(port_, lldpctl_k_port_dot3_aggregid);
  row_["port_description"] = getAtomStr(port_, lldpctl_k_port_descr);
  row_["port_ttl"] = getAtomStr(port_, lldpctl_k_port_age);
  row_["port_mfs"] = getAtomStr(port_, lldpctl_k_port_dot3_mfs);

  // Dot3 power stuff
  std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> power(
      lldpctl_atom_get(port_, lldpctl_k_port_dot3_power), delLLDPAtom);
  auto pp = power.get();
  if (pp != nullptr &&
      lldpctl_atom_get_int(pp, lldpctl_k_dot3_power_devicetype) > 0) {
    row_["power_device_type"] = getAtomStr(pp, lldpctl_k_dot3_power_devicetype);
    row_["power_mdi_supported"] =
        lldpctl_atom_get_int(pp, lldpctl_k_dot3_power_supported);
    row_["power_mdi_enabled"] =
        lldpctl_atom_get_int(pp, lldpctl_k_dot3_power_enabled);
    row_["power_paircontrol_enabled"] =
        lldpctl_atom_get_int(pp, lldpctl_k_dot3_power_paircontrol);
    row_["power_pairs"] = getAtomStr(pp, lldpctl_k_dot3_power_pairs);
    row_["power_class"] = getAtomStr(pp, lldpctl_k_dot3_power_class);
    row_["power_8023at_enabled"] =
        (lldpctl_atom_get_int(pp, lldpctl_k_dot3_power_type) >
         LLDP_DOT3_POWER_8023AT_OFF);
    row_["power_8023at_power_type"] = getAtomStr(pp, lldpctl_k_dot3_power_type);
    row_["power_8023at_power_source"] =
        getAtomStr(pp, lldpctl_k_dot3_power_source);
    row_["power_8023at_power_priority"] =
        getAtomStr(pp, lldpctl_k_dot3_power_priority);
    row_["power_8023at_power_requested"] =
        getAtomStr(pp, lldpctl_k_dot3_power_requested);
    row_["power_8023at_power_allocated"] =
        getAtomStr(pp, lldpctl_k_dot3_power_allocated);
  }

  // Auto-Negotiations
  bool autoneg_supported =
      lldpctl_atom_get_int(port_, lldpctl_k_port_dot3_autoneg_support);
  row_["port_autoneg_supported"] = (autoneg_supported) ? "1" : "0";

  bool autoneg_enabled =
      lldpctl_atom_get_int(port_, lldpctl_k_port_dot3_autoneg_enabled);
  row_["port_autoneg_enabled"] = (autoneg_enabled) ? "1" : "0";

  row_["port_mau_type"] = getAtomStr(port_, lldpctl_k_port_dot3_mautype);

  if (autoneg_supported && autoneg_enabled) {
    long int advertised =
        lldpctl_atom_get_int(port_, lldpctl_k_port_dot3_autoneg_advertised);

    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_10BASE_T,
                  LLDP_DOT3_LINK_AUTONEG_10BASET_FD,
                  "port_autoneg_10baset_hd_enabled",
                  "port_autoneg_10baset_fd_enabled");
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_TX,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD,
                  "port_autoneg_100basetx_hd_enabled",
                  "port_autoneg_100basetx_fd_enabled");
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T2,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T2FD,
                  "port_autoneg_100baset2_hd_enabled",
                  "port_autoneg_100baset2_fd_enabled");
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                  "port_autoneg_100baset4_hd_enabled",
                  "port_autoneg_100baset4_fd_enabled");
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_X,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_XFD,
                  "port_autoneg_1000basex_hd_enabled",
                  "port_autoneg_1000basex_fd_enabled");
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_T,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_TFD,
                  "port_autoneg_1000baset_hd_enabled",
                  "port_autoneg_1000baset_fd_enabled");
  }
}

void LLDPNeighbor::getChassis() {
  row_["rid"] = getAtomStr(chassis_, lldpctl_k_chassis_index);
  row_["chassis_id"] = getAtomStr(chassis_, lldpctl_k_chassis_id);
  row_["chassis_id_type"] = getAtomStr(chassis_, lldpctl_k_chassis_id_subtype);
  row_["chassis_sysname"] = getAtomStr(chassis_, lldpctl_k_chassis_name);
  row_["chassis_sys_description"] =
      getAtomStr(chassis_, lldpctl_k_chassis_descr);

  getChasisCapability(LLDP_CAP_BRIDGE,
                      "chassis_bridge_capability_available",
                      "chassis_bridge_capability_enabled");
  getChasisCapability(LLDP_CAP_ROUTER,
                      "chassis_router_capability_available",
                      "chassis_router_capability_enabled");
  getChasisCapability(LLDP_CAP_WLAN,
                      "chassis_wlan_capability_available",
                      "chassis_wlan_capability_enabled");
  getChasisCapability(LLDP_CAP_REPEATER,
                      "chassis_repeater_capability_available",
                      "chassis_repeater_capability_enabled");
  getChasisCapability(LLDP_CAP_TELEPHONE,
                      "chassis_tel_capability_available",
                      "chassis_tel_capability_enabled");
  getChasisCapability(LLDP_CAP_DOCSIS,
                      "chassis_docsis_capability_available",
                      "chassis_docsis_capability_enabled");
  getChasisCapability(LLDP_CAP_STATION,
                      "chassis_station_capability_available",
                      "chassis_station_capability_enabled");
  getChasisCapability(LLDP_CAP_OTHER,
                      "chassis_other_capability_available",
                      "chassis_other_capability_enabled");

  std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> mgmts(
      lldpctl_atom_get(chassis_, lldpctl_k_chassis_mgmt), delLLDPAtom);
  row_["chassis_mgmt_ips"] = commaDelimitedStr(mgmts.get(), lldpctl_k_mgmt_ip);
}

/**
 * @brief getNeighbor retrieves all LLDP information of the given neighbor port
 * and chassis.
 *
 * @return filled osquery::Row of lldp information for a given interface
 *
 */
Row& LLDPNeighbor::getNeighbor() {
  getChassis();
  getPort();
  getVLAN();
  getMED();
  getMEDCap();
  getPIDs();
  getPPVIDs();

  return row_;
}

QueryData genLLDPNeighbors(QueryContext& context) {
  QueryData rows;

  auto delConn = [](lldpctl_conn_t* c) { lldpctl_release(c); };
  std::unique_ptr<lldpctl_conn_t, decltype(delConn)> conn(
      lldpctl_new(nullptr, nullptr, nullptr), delConn);

  lldpctl_error_t err = lldpctl_last_error(conn.get());
  if (err != LLDPCTL_NO_ERROR) {
    LOG(ERROR) << "could not initiate new lldpd connection: "
               << lldpctl_strerror(err);
    return rows;
  }

  std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> interfaces(
      lldpctl_get_interfaces(conn.get()), delLLDPAtom);

  err = lldpctl_last_error(conn.get());
  if (err != LLDPCTL_NO_ERROR) {
    LOG(WARNING) << "could not connect to lldpd (hint: you might need to "
                    "install lldpd v0.9.X or run in sudo): "
                 << lldpctl_strerror(err);
    return rows;
  }

  lldpctl_atom_t* interface = nullptr;
  lldpctl_atom_foreach(interfaces.get(), interface) {
    std::string ifaceName = getAtomStr(interface, lldpctl_k_interface_name);

    std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> port(
        lldpctl_get_port(interface), delLLDPAtom);
    std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> neighbors(
        lldpctl_atom_get(port.get(), lldpctl_k_port_neighbors), delLLDPAtom);

    lldpctl_atom_t* neighbor = nullptr;
    lldpctl_atom_foreach(neighbors.get(), neighbor) {
      std::unique_ptr<lldpctl_atom_t, decltype(delLLDPAtom)> chassis(
          lldpctl_atom_get(neighbor, lldpctl_k_port_chassis), delLLDPAtom);

      LLDPNeighbor n(neighbor, chassis.get());
      Row& row = n.getNeighbor();
      row["interface"] = ifaceName;
      rows.push_back(row);
    }
  }

  return rows;
}
}
}
