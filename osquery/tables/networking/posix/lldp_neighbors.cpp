/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include <lldp-const.h>
#include <lldpctl.h>

namespace osquery {
namespace tables {

// Column constants for lldp_neighbors table
const std::string kColInterface = "interface";
const std::string kColChassisIndex = "rid";
const std::string kColChassisIdType = "chassis_id_type";
const std::string kColChassisId = "chassis_id";
const std::string kColChassisSysname = "chassis_sysname";
const std::string kColChassisSysDesc = "chassis_sys_description";
const std::string kColChassisBridgeCapabilityAvailable =
    "chassis_bridge_capability_available";
const std::string kColChassisBridgeCapabilityEnabled =
    "chassis_bridge_capability_enabled";
const std::string kColChassisRouterCapabilityAvailable =
    "chassis_router_capability_available";
const std::string kColChassisRouterCapabilityEnabled =
    "chassis_router_capability_enabled";
const std::string kColChassisRepeaterCapabilityAvailable =
    "chassis_repeater_capability_available";
const std::string kColChassisRepeaterCapabilityEnabled =
    "chassis_repeater_capability_enabled";
const std::string kColChassisWLANCapabilityAvailable =
    "chassis_wlan_capability_available";
const std::string kColChassisWLANCapabilityEnabled =
    "chassis_wlan_capability_enabled";
const std::string kColChassisTelCapabilityAvailable =
    "chassis_tel_capability_available";
const std::string kColChassisTelCapabilityEnabled =
    "chassis_tel_capability_enabled";
const std::string kColChassisDOCSISCapabilityAvailable =
    "chassis_docsis_capability_available";
const std::string kColChassisDOCSISCapabilityEnabled =
    "chassis_docsis_capability_enabled";
const std::string kColChassisStationCapabilityAvailable =
    "chassis_station_capability_available";
const std::string kColChassisStationCapabilityEnabled =
    "chassis_station_capability_enabled";
const std::string kColChassisOtherCapabilityAvailable =
    "chassis_other_capability_available";
const std::string kColChassisOtherCapabilityEnabled =
    "chassis_other_capability_enabled";
const std::string kColChassisMgmtIPs = "chassis_mgmt_ips";
const std::string kColPortIdType = "port_id_type";
const std::string kColPortId = "port_id";
const std::string kColPortDesc = "port_description";
const std::string kColPortAge = "port_ttl";
const std::string kColPortMFS = "port_mfs";
const std::string kColPortAggrId = "port_aggregation_id";
const std::string kColPortAutonegSupported = "port_autoneg_supported";
const std::string kColPortAutonegEnabled = "port_autoneg_enabled";
const std::string kColPortMauType = "port_mau_type";
const std::string kColPortAutoneg10BaseTHDEnabled =
    "port_autoneg_10baset_hd_enabled";
const std::string kColPortAutoneg10BaseTFDEnabled =
    "port_autoneg_10baset_fd_enabled";
const std::string kColPortAutoNeg100BaseTXHDEnabled =
    "port_autoneg_100basetx_hd_enabled";
const std::string kColPortAutoneg100BaseTXFDEnabled =
    "port_autoneg_100basetx_fd_enabled";
const std::string kColAutoNeg100BaseT2HDEnabled =
    "port_autoneg_100baset2_hd_enabled";
const std::string kColAutoNeg100BaseT2FDEnabled =
    "port_autoneg_100baset2_fd_enabled";
const std::string kColPortAutoneg100BaseT4HDEnabled =
    "port_autoneg_100baset4_hd_enabled";
const std::string kColPortAutoneg100BaseT4FDEnabled =
    "port_autoneg_100baset4_fd_enabled";
const std::string kColPortAutoneg1000BaseXHDEnabled =
    "port_autoneg_1000basex_hd_enabled";
const std::string kColPortAutoneg1000BaseXFDEnabled =
    "port_autoneg_1000basex_fd_enabled";
const std::string kColPortAutoneg1000BaseTHDEnabled =
    "port_autoneg_1000baset_hd_enabled";
const std::string kColPortAutoneg1000BaseTFDEnabled =
    "port_autoneg_1000baset_fd_enabled";
const std::string kColPowerDeviceType = "power_device_type";
const std::string kColPowerMDISupported = "power_mdi_supported";
const std::string kColPowerMDIEnabled = "power_mdi_enabled";
const std::string kColPowerPairControlEnabled = "power_paircontrol_enabled";
const std::string kColPowerPairs = "power_pairs";
const std::string kColPowerClass = "power_class";
const std::string kColPower8023atEnabled = "power_8023at_enabled";
const std::string kColPower8023atPowerType = "power_8023at_power_type";
const std::string kColPower8023atPowerSource = "power_8023at_power_source";
const std::string kColPower8023atPowerPriority = "power_8023at_power_priority";
const std::string kColPower8023atPowerAllocated =
    "power_8023at_power_allocated";
const std::string kColPower8023atPowerRequested =
    "power_8023at_power_requested";
const std::string kColVLANS = "vlans";
const std::string kColPVID = "pvid";
const std::string kColPPVIDsSupported = "ppvids_supported";
const std::string kColPPVIDsEnabled = "ppvids_enabled";
const std::string kColPIDs = "pids";
const std::string kColMEDType = "med_device_type";
const std::string kColMEDCapabilityCapabilities = "med_capability_capabilities";
const std::string kColMEDCapabilityPolicy = "med_capability_policy";
const std::string kColMEDCapabilityLocation = "med_capability_location";
const std::string kColMEDCapabilityMDIPSE = "med_capability_mdi_pse";
const std::string kColMEDCapabilityMDIPD = "med_capability_mdi_pd";
const std::string kColMEDCapabilityInventory = "med_capability_inventory";
const std::string kColMEDPolicies = "med_policies";

/* kNoAtomStrDefault is the default value used when lldp_atom_get_str does not
 * return a valid string value. */
const std::string kNoAtomStrDefault = "unknown";

struct ChassisCapability {
  bool available;
  bool enabled;
};

inline std::string getAtomStr(lldpctl_atom_t* atom, lldpctl_key_t key) {
  if (!atom) {
    return kNoAtomStrDefault;
  }

  const char* val = lldpctl_atom_get_str(atom, key);
  if (val == NULL) {
    return kNoAtomStrDefault;
  }

  return val;
}

inline std::string commaDelimitedStr(lldpctl_atom_t* things,
                                     lldpctl_key_t key) {
  if (!things) {
    return "";
  }

  std::string result;
  lldpctl_atom_t* each;

  lldpctl_atom_foreach(things, each) {
    result = result + getAtomStr(each, key) + ",";
  }
  // Remove trailing comma.
  if (result.size() > 0) {
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
                           std::string availCol,
                           std::string enabledCol);
  void getPort();
  void getPMDAutoNeg(long int autonegAdversised,
                     long int hdMask,
                     long int fdMask,
                     std::string hdCol,
                     std::string fdCol);
  void getVLAN();
  void getMED();
  void getMEDCap();
  void getPIDs();
  void getPPVIDs();
};

inline void LLDPNeighbor::getChasisCapability(u_int8_t mask,
                                              std::string availCol,
                                              std::string enabledCol) {
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
                                        std::string hdCol,
                                        std::string fdCol) {
  row_[hdCol] = ((autonegAdversised & hdMask) ? "1" : "0");
  row_[fdCol] = ((autonegAdversised & fdMask) ? "1" : "0");
}

void LLDPNeighbor::getPIDs() {
  lldpctl_atom_t* pids = lldpctl_atom_get(port_, lldpctl_k_port_pis);
  row_[kColPIDs] = commaDelimitedStr(pids, lldpctl_k_pi_id);

  lldpctl_atom_dec_ref(pids);
}

void LLDPNeighbor::getPPVIDs() {
  lldpctl_atom_t* ppvids = lldpctl_atom_get(port_, lldpctl_k_port_ppvids);
  if (!ppvids) {
    return;
  }

  std::string supported;
  std::string enabled;

  lldpctl_atom_t* ppvid;
  lldpctl_atom_foreach(ppvids, ppvid) {
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
  row_[kColPPVIDsSupported] = supported;

  if (enabled.size() > 0) {
    enabled.pop_back();
  }
  row_[kColPPVIDsEnabled] = enabled;

  lldpctl_atom_dec_ref(ppvids);
}

void LLDPNeighbor::getMEDCap() {
  long int availableCap =
      lldpctl_atom_get_int(chassis_, lldpctl_k_chassis_med_cap);
  if (availableCap < 0) {
    return;
  }

  row_[kColMEDCapabilityCapabilities] =
      (availableCap & LLDP_MED_CAP_CAP) ? "1" : "0";
  row_[kColMEDCapabilityPolicy] =
      (availableCap & LLDP_MED_CAP_POLICY) ? "1" : "0";
  row_[kColMEDCapabilityLocation] =
      (availableCap & LLDP_MED_CAP_LOCATION) ? "1" : "0";
  row_[kColMEDCapabilityMDIPSE] =
      (availableCap & LLDP_MED_CAP_MDI_PSE) ? "1" : "0";
  row_[kColMEDCapabilityMDIPD] =
      (availableCap & LLDP_MED_CAP_MDI_PD) ? "1" : "0";
  row_[kColMEDCapabilityInventory] =
      (availableCap & LLDP_MED_CAP_IV) ? "1" : "0";
}

void LLDPNeighbor::getMED() {
  if (lldpctl_atom_get_int(chassis_, lldpctl_k_chassis_med_type) <= 0) {
    return;
  }

  row_[kColMEDType] = getAtomStr(chassis_, lldpctl_k_chassis_med_type);
  // Capabilities status
  getMEDCap();

  // Policy Capabilities
  // TODO add MED policy tags and defined/undefined tags
  lldpctl_atom_t* policies =
      lldpctl_atom_get(port_, lldpctl_k_port_med_policies);
  row_[kColMEDPolicies] =
      commaDelimitedStr(policies, lldpctl_k_med_policy_type);

  lldpctl_atom_dec_ref(policies);

  // TODO add MED Location, Power, Inventory details.
}

void LLDPNeighbor::getVLAN() {
  row_[kColPVID] = getAtomStr(port_, lldpctl_k_port_vlan_pvid);

  lldpctl_atom_t* vlans = lldpctl_atom_get(port_, lldpctl_k_port_vlans);
  row_[kColVLANS] = commaDelimitedStr(vlans, lldpctl_k_vlan_id);

  lldpctl_atom_dec_ref(vlans);
}

void LLDPNeighbor::getPort() {
  row_[kColPortId] = getAtomStr(port_, lldpctl_k_port_id);
  row_[kColPortIdType] = getAtomStr(port_, lldpctl_k_port_id_subtype);
  row_[kColPortAggrId] = getAtomStr(port_, lldpctl_k_port_dot3_aggregid);
  row_[kColPortDesc] = getAtomStr(port_, lldpctl_k_port_descr);
  row_[kColPortAge] = getAtomStr(port_, lldpctl_k_port_age);
  row_[kColPortMFS] = getAtomStr(port_, lldpctl_k_port_dot3_mfs);

  // Dot3 power stuff
  lldpctl_atom_t* power = lldpctl_atom_get(port_, lldpctl_k_port_dot3_power);
  if (power &&
      lldpctl_atom_get_int(power, lldpctl_k_dot3_power_devicetype) > 0) {
    row_[kColPowerDeviceType] =
        getAtomStr(power, lldpctl_k_dot3_power_devicetype);
    row_[kColPowerMDISupported] =
        lldpctl_atom_get_int(power, lldpctl_k_dot3_power_supported);
    row_[kColPowerMDIEnabled] =
        lldpctl_atom_get_int(power, lldpctl_k_dot3_power_enabled);
    row_[kColPowerPairControlEnabled] =
        lldpctl_atom_get_int(power, lldpctl_k_dot3_power_paircontrol);
    row_[kColPowerPairs] = getAtomStr(power, lldpctl_k_dot3_power_pairs);
    row_[kColPowerClass] = getAtomStr(power, lldpctl_k_dot3_power_class);
    row_[kColPower8023atEnabled] =
        (lldpctl_atom_get_int(power, lldpctl_k_dot3_power_type) >
         LLDP_DOT3_POWER_8023AT_OFF);
    row_[kColPower8023atPowerType] =
        getAtomStr(power, lldpctl_k_dot3_power_type);
    row_[kColPower8023atPowerSource] =
        getAtomStr(power, lldpctl_k_dot3_power_source);
    row_[kColPower8023atPowerPriority] =
        getAtomStr(power, lldpctl_k_dot3_power_priority);
    row_[kColPower8023atPowerRequested] =
        getAtomStr(power, lldpctl_k_dot3_power_requested);
    row_[kColPower8023atPowerAllocated] =
        getAtomStr(power, lldpctl_k_dot3_power_allocated);
  }
  lldpctl_atom_dec_ref(power);

  // Auto-Negotiations
  bool autoneg_supported =
      lldpctl_atom_get_int(port_, lldpctl_k_port_dot3_autoneg_support);
  row_[kColPortAutonegSupported] = (autoneg_supported) ? "1" : "0";

  bool autoneg_enabled =
      lldpctl_atom_get_int(port_, lldpctl_k_port_dot3_autoneg_enabled);
  row_[kColPortAutonegEnabled] = (autoneg_enabled) ? "1" : "0";

  row_[kColPortMauType] = getAtomStr(port_, lldpctl_k_port_dot3_mautype);

  if (autoneg_supported && autoneg_enabled) {
    long int advertised =
        lldpctl_atom_get_int(port_, lldpctl_k_port_dot3_autoneg_advertised);

    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_10BASE_T,
                  LLDP_DOT3_LINK_AUTONEG_10BASET_FD,
                  kColPortAutoneg10BaseTHDEnabled,
                  kColPortAutoneg10BaseTFDEnabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_TX,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD,
                  kColPortAutoNeg100BaseTXHDEnabled,
                  kColPortAutoneg100BaseTXFDEnabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T2,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T2FD,
                  kColAutoNeg100BaseT2HDEnabled,
                  kColAutoNeg100BaseT2FDEnabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                  kColPortAutoneg100BaseT4HDEnabled,
                  kColPortAutoneg100BaseT4FDEnabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_X,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_XFD,
                  kColPortAutoneg1000BaseXHDEnabled,
                  kColPortAutoneg1000BaseXFDEnabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_T,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_TFD,
                  kColPortAutoneg1000BaseTHDEnabled,
                  kColPortAutoneg1000BaseTFDEnabled);
  }
}

void LLDPNeighbor::getChassis() {
  row_[kColChassisIndex] = getAtomStr(chassis_, lldpctl_k_chassis_index);
  row_[kColChassisId] = getAtomStr(chassis_, lldpctl_k_chassis_id);
  row_[kColChassisIdType] = getAtomStr(chassis_, lldpctl_k_chassis_id_subtype);
  row_[kColChassisSysname] = getAtomStr(chassis_, lldpctl_k_chassis_name);
  row_[kColChassisSysDesc] = getAtomStr(chassis_, lldpctl_k_chassis_descr);

  getChasisCapability(LLDP_CAP_BRIDGE,
                      kColChassisBridgeCapabilityAvailable,
                      kColChassisBridgeCapabilityEnabled);
  getChasisCapability(LLDP_CAP_ROUTER,
                      kColChassisRouterCapabilityAvailable,
                      kColChassisRouterCapabilityEnabled);
  getChasisCapability(LLDP_CAP_WLAN,
                      kColChassisWLANCapabilityAvailable,
                      kColChassisWLANCapabilityEnabled);
  getChasisCapability(LLDP_CAP_REPEATER,
                      kColChassisRepeaterCapabilityAvailable,
                      kColChassisRepeaterCapabilityEnabled);
  getChasisCapability(LLDP_CAP_TELEPHONE,
                      kColChassisTelCapabilityAvailable,
                      kColChassisTelCapabilityEnabled);
  getChasisCapability(LLDP_CAP_DOCSIS,
                      kColChassisDOCSISCapabilityAvailable,
                      kColChassisDOCSISCapabilityEnabled);
  getChasisCapability(LLDP_CAP_STATION,
                      kColChassisStationCapabilityAvailable,
                      kColChassisStationCapabilityEnabled);
  getChasisCapability(LLDP_CAP_OTHER,
                      kColChassisOtherCapabilityAvailable,
                      kColChassisOtherCapabilityEnabled);

  lldpctl_atom_t* mgmts = lldpctl_atom_get(chassis_, lldpctl_k_chassis_mgmt);
  row_[kColChassisMgmtIPs] = commaDelimitedStr(mgmts, lldpctl_k_mgmt_ip);
  lldpctl_atom_dec_ref(mgmts);
}

/**
 * @brief getNeighbor retreives all LLDP information of the given neighbor port
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

  lldpctl_conn_t* conn(lldpctl_new(nullptr, nullptr, nullptr));
  lldpctl_error_t err = lldpctl_last_error(conn);
  if (err != LLDPCTL_NO_ERROR) {
    LOG(ERROR) << "could not initiate new lldpd connection: "
               << lldpctl_strerror(err);
    return rows;
  }

  lldpctl_atom_t* interfaces = lldpctl_get_interfaces(conn);
  err = lldpctl_last_error(conn);
  if (err != LLDPCTL_NO_ERROR) {
    LOG(WARNING) << "could not connect to lldpd (hint: you might need to "
                    "install lldpd v0.9.X or run in sudo): "
                 << lldpctl_strerror(err);
    return rows;
  }

  lldpctl_atom_t* interface;
  lldpctl_atom_foreach(interfaces, interface) {
    std::string ifaceName = getAtomStr(interface, lldpctl_k_interface_name);
    lldpctl_atom_t* port = lldpctl_get_port(interface);

    lldpctl_atom_t* neighbors =
        lldpctl_atom_get(port, lldpctl_k_port_neighbors);
    lldpctl_atom_t* neighbor;
    lldpctl_atom_foreach(neighbors, neighbor) {
      lldpctl_atom_t* chassis =
          lldpctl_atom_get(neighbor, lldpctl_k_port_chassis);

      LLDPNeighbor n(neighbor, chassis);
      Row& row = n.getNeighbor();
      row[kColInterface] = ifaceName;
      rows.push_back(row);

      lldpctl_atom_dec_ref(chassis);
    }

    lldpctl_atom_dec_ref(neighbors);
    lldpctl_atom_dec_ref(port);
  }

  lldpctl_atom_dec_ref(interfaces);
  lldpctl_release(conn);

  return rows;
}
}
}
