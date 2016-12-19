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

/* Column constants for lldp_neighbors table */
const std::string col_interface = "interface";
const std::string col_chassis_index = "rid";
const std::string col_chassis_id_type = "chassis_id_type";
const std::string col_chassis_id = "chassis_id";
const std::string col_chassis_sysname = "chassis_sysname";
const std::string col_chassis_sys_desc = "chassis_sys_description";
const std::string col_chassis_bridge_capability_available =
    "chassis_bridge_capability_available";
const std::string col_chassis_bridge_capability_enabled =
    "chassis_bridge_capability_enabled";
const std::string col_chassis_router_capability_available =
    "chassis_router_capability_available";
const std::string col_chassis_router_capability_enabled =
    "chassis_router_capability_enabled";
const std::string col_chassis_repeater_capability_available =
    "chassis_repeater_capability_available";
const std::string col_chassis_repeater_capability_enabled =
    "chassis_repeater_capability_enabled";
const std::string col_chassis_wlan_capability_available =
    "chassis_wlan_capability_available";
const std::string col_chassis_wlan_capability_enabled =
    "chassis_wlan_capability_enabled";
const std::string col_chassis_tel_capability_available =
    "chassis_tel_capability_available";
const std::string col_chassis_tel_capability_enabled =
    "chassis_tel_capability_enabled";
const std::string col_chassis_docsis_capability_available =
    "chassis_docsis_capability_available";
const std::string col_chassis_docsis_capability_enabled =
    "chassis_docsis_capability_enabled";
const std::string col_chassis_station_capability_available =
    "chassis_station_capability_available";
const std::string col_chassis_station_capability_enabled =
    "chassis_station_capability_enabled";
const std::string col_chassis_other_capability_available =
    "chassis_other_capability_available";
const std::string col_chassis_other_capability_enabled =
    "chassis_other_capability_enabled";
const std::string col_chassis_mgmt_ips = "chassis_mgmt_ips";
const std::string col_port_id_type = "port_id_type";
const std::string col_port_id = "port_id";
const std::string col_port_desc = "port_description";
const std::string col_port_age = "port_ttl";
const std::string col_port_mfs = "port_mfs";
const std::string col_port_aggr_id = "port_aggregation_id";
const std::string col_port_autoneg_supported = "port_autoneg_supported";
const std::string col_port_autoneg_enabled = "port_autoneg_enabled";
const std::string col_port_mau_type = "port_mau_type";
const std::string col_port_autoneg_10baset_hd_enabled =
    "port_autoneg_10baset_hd_enabled";
const std::string col_port_autoneg_10baset_fd_enabled =
    "port_autoneg_10baset_fd_enabled";
const std::string col_port_autoneg_100basetx_hd_enabled =
    "port_autoneg_100basetx_hd_enabled";
const std::string col_port_autoneg_100basetx_fd_enabled =
    "port_autoneg_100basetx_fd_enabled";
const std::string col_port_autoneg_100baset2_hd_enabled =
    "port_autoneg_100baset2_hd_enabled";
const std::string col_port_autoneg_100baset2_fd_enabled =
    "port_autoneg_100baset2_fd_enabled";
const std::string col_port_autoneg_100baset4_hd_enabled =
    "port_autoneg_100baset4_hd_enabled";
const std::string col_port_autoneg_100baset4_fd_enabled =
    "port_autoneg_100baset4_fd_enabled";
const std::string col_port_autoneg_1000basex_hd_enabled =
    "port_autoneg_1000basex_hd_enabled";
const std::string col_port_autoneg_1000basex_fd_enabled =
    "port_autoneg_1000basex_fd_enabled";
const std::string col_port_autoneg_1000baset_hd_enabled =
    "port_autoneg_1000baset_hd_enabled";
const std::string col_port_autoneg_1000baset_fd_enabled =
    "port_autoneg_1000baset_fd_enabled";
const std::string col_power_device_type = "power_device_type";
const std::string col_power_mdi_supported = "power_mdi_supported";
const std::string col_power_mdi_enabled = "power_mdi_enabled";
const std::string col_power_paircontrol_enabled = "power_paircontrol_enabled";
const std::string col_power_pairs = "power_pairs";
const std::string col_power_class = "power_class";
const std::string col_power_8023at_enabled = "power_8023at_enabled";
const std::string col_power_8023at_power_type = "power_8023at_power_type";
const std::string col_power_8023at_power_source = "power_8023at_power_source";
const std::string col_power_8023at_power_priority =
    "power_8023at_power_priority";
const std::string col_power_8023at_power_allocated =
    "power_8023at_power_allocated";
const std::string col_power_8023at_power_requested =
    "power_8023at_power_requested";
const std::string col_vlans = "vlans";
const std::string col_pvid = "pvid";
const std::string col_ppvids_supported = "ppvids_supported";
const std::string col_ppvids_enabled = "ppvids_enabled";
const std::string col_pids = "pids";
const std::string col_med_type = "med_device_type";
const std::string col_med_capability_capabilities =
    "med_capability_capabilities";
const std::string col_med_capability_policy = "med_capability_policy";
const std::string col_med_capability_location = "med_capability_location";
const std::string col_med_capability_mdi_pse = "med_capability_mdi_pse";
const std::string col_med_capability_mdi_pd = "med_capability_mdi_pd";
const std::string col_med_capability_inventory = "med_capability_inventory";
const std::string col_med_policies = "med_policies";

// no_atom_str_default is the default value used when lldp_atom_get_str does
// not return a valid string value.
const std::string no_atom_str_default = "unknown";

// Stub typedefs. Remove later
// typedef std::map<std::string, std::string> Row;
// typedef std::vector<Row> QueryData;

struct ChassisCapability {
  bool available;
  bool enabled;
};

inline std::string getAtomStr(lldpctl_atom_t* atom, lldpctl_key_t key) {
  if (!atom) {
    return no_atom_str_default;
  }

  const char* val = lldpctl_atom_get_str(atom, key);
  if (val == NULL) {
    return no_atom_str_default;
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

/**
 * LLDPNeighbor is responsible for retrieving LLDP information on one neighbor.
 *
 * It does not handle the the reference decrementing of the chassis and port
 * parameter.  That responsibility is on the caller.
 */
class LLDPNeighbor {
 public:
  LLDPNeighbor(lldpctl_atom_t* port, lldpctl_atom_t* chassis)
      : m_port(port), m_chassis(chassis) {}

  LLDPNeighbor(const LLDPNeighbor& ln) = delete;

  Row& getNeighbor();

 private:
  lldpctl_atom_t* m_port;
  lldpctl_atom_t* m_chassis;
  Row m_row;

  void getChassis();
  void getChasisCapability(u_int8_t mask,
                           std::string avail_col,
                           std::string enabled_col);
  void getPort();
  void getPMDAutoNeg(long int autonegAdversised,
                     long int hdMask,
                     long int fdMask,
                     std::string hd_col,
                     std::string fd_col);
  void getVLAN();
  void getMED();
  void getMEDCap();
  void getPIDs();
  void getPPVIDs();
};

class LLDPNeighbors {
 private:
  lldpctl_conn_t* m_conn;
  QueryData m_rows;

 public:
  LLDPNeighbors() : m_conn(lldpctl_new(nullptr, nullptr, nullptr)) {}
  ~LLDPNeighbors() {
    lldpctl_release(m_conn);
  }

  /**
   * getAllNeighbors retreives all LLDP neighbors of network interfaces.
   *
   * Returns a osquery::QueryData.
   */
  QueryData& getAllNeighbors() {
    lldpctl_error_t err = lldpctl_last_error(m_conn);
    if (err != LLDPCTL_NO_ERROR) {
      LOG(ERROR) << "could not get lldp neighbors: " +
                        static_cast<std::string>(lldpctl_strerror(err)) + "\n";
      // TODO log error with osquery logging api and  lldpctl_strerror func
      // call
      return m_rows;
    }

    std::string iface_name;

    lldpctl_atom_t* interfaces = lldpctl_get_interfaces(m_conn);
    lldpctl_atom_t* interface;
    lldpctl_atom_foreach(interfaces, interface) {
      iface_name = getAtomStr(interface, lldpctl_k_interface_name);
      lldpctl_atom_t* port = lldpctl_get_port(interface);

      lldpctl_atom_t* neighbors =
          lldpctl_atom_get(port, lldpctl_k_port_neighbors);
      lldpctl_atom_t* neighbor;
      lldpctl_atom_foreach(neighbors, neighbor) {
        lldpctl_atom_t* chassis =
            lldpctl_atom_get(neighbor, lldpctl_k_port_chassis);

        LLDPNeighbor n(neighbor, chassis);
        Row& row = n.getNeighbor();
        row[col_interface] = iface_name;
        m_rows.push_back(row);

        lldpctl_atom_dec_ref(chassis);
      }

      lldpctl_atom_dec_ref(neighbors);
      lldpctl_atom_dec_ref(port);
    }

    lldpctl_atom_dec_ref(interfaces);

    return m_rows;
  }
};

inline void LLDPNeighbor::getChasisCapability(u_int8_t mask,
                                              std::string avail_col,
                                              std::string enabled_col) {
  if (lldpctl_atom_get_int(m_chassis, lldpctl_k_chassis_cap_available) & mask) {
    m_row[avail_col] = "1";
    m_row[enabled_col] =
        (lldpctl_atom_get_int(m_chassis, lldpctl_k_chassis_cap_enabled) & mask)
            ? "1"
            : "0";
  }
}

inline void LLDPNeighbor::getPMDAutoNeg(long int autonegAdversised,
                                        long int hdMask,
                                        long int fdMask,
                                        std::string hd_col,
                                        std::string fd_col) {
  m_row[hd_col] = ((autonegAdversised & hdMask) ? "1" : "0");
  m_row[fd_col] = ((autonegAdversised & fdMask) ? "1" : "0");
}

void LLDPNeighbor::getPIDs() {
  lldpctl_atom_t* pids = lldpctl_atom_get(m_port, lldpctl_k_port_pis);
  m_row[col_pids] = commaDelimitedStr(pids, lldpctl_k_pi_id);

  lldpctl_atom_dec_ref(pids);
}

void LLDPNeighbor::getPPVIDs() {
  lldpctl_atom_t* ppvids = lldpctl_atom_get(m_port, lldpctl_k_port_ppvids);
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
  m_row[col_ppvids_supported] = supported;

  if (enabled.size() > 0) {
    enabled.pop_back();
  }
  m_row[col_ppvids_enabled] = enabled;

  lldpctl_atom_dec_ref(ppvids);
}

void LLDPNeighbor::getMEDCap() {
  long int availableCap =
      lldpctl_atom_get_int(m_chassis, lldpctl_k_chassis_med_cap);
  if (availableCap < 0) {
    return;
  }

  m_row[col_med_capability_capabilities] =
      (availableCap & LLDP_MED_CAP_CAP) ? "1" : "0";
  m_row[col_med_capability_policy] =
      (availableCap & LLDP_MED_CAP_POLICY) ? "1" : "0";
  m_row[col_med_capability_location] =
      (availableCap & LLDP_MED_CAP_LOCATION) ? "1" : "0";
  m_row[col_med_capability_mdi_pse] =
      (availableCap & LLDP_MED_CAP_MDI_PSE) ? "1" : "0";
  m_row[col_med_capability_mdi_pd] =
      (availableCap & LLDP_MED_CAP_MDI_PD) ? "1" : "0";
  m_row[col_med_capability_inventory] =
      (availableCap & LLDP_MED_CAP_IV) ? "1" : "0";
}

void LLDPNeighbor::getMED() {
  if (lldpctl_atom_get_int(m_chassis, lldpctl_k_chassis_med_type) <= 0) {
    return;
  }

  m_row[col_med_type] = getAtomStr(m_chassis, lldpctl_k_chassis_med_type);
  // Capabilities status
  getMEDCap();

  // Policy Capabilities
  // TODO add MED policy tags and defined/undefined tags
  lldpctl_atom_t* policies =
      lldpctl_atom_get(m_port, lldpctl_k_port_med_policies);
  m_row[col_med_policies] =
      commaDelimitedStr(policies, lldpctl_k_med_policy_type);

  lldpctl_atom_dec_ref(policies);

  // TODO add MED Location, Power, Inventory details.
}

void LLDPNeighbor::getVLAN() {
  m_row[col_pvid] = getAtomStr(m_port, lldpctl_k_port_vlan_pvid);

  lldpctl_atom_t* vlans = lldpctl_atom_get(m_port, lldpctl_k_port_vlans);
  m_row[col_vlans] = commaDelimitedStr(vlans, lldpctl_k_vlan_id);

  lldpctl_atom_dec_ref(vlans);
}

void LLDPNeighbor::getPort() {
  m_row[col_port_id] = getAtomStr(m_port, lldpctl_k_port_id);
  m_row[col_port_id_type] = getAtomStr(m_port, lldpctl_k_port_id_subtype);
  m_row[col_port_aggr_id] = getAtomStr(m_port, lldpctl_k_port_dot3_aggregid);
  m_row[col_port_desc] = getAtomStr(m_port, lldpctl_k_port_descr);
  m_row[col_port_age] = getAtomStr(m_port, lldpctl_k_port_age);
  m_row[col_port_mfs] = getAtomStr(m_port, lldpctl_k_port_dot3_mfs);

  // Dot3 power stuff
  lldpctl_atom_t* power = lldpctl_atom_get(m_port, lldpctl_k_port_dot3_power);
  if (power &&
      lldpctl_atom_get_int(power, lldpctl_k_dot3_power_devicetype) > 0) {
    m_row[col_power_device_type] =
        getAtomStr(power, lldpctl_k_dot3_power_devicetype);
    m_row[col_power_mdi_supported] =
        lldpctl_atom_get_int(power, lldpctl_k_dot3_power_supported);
    m_row[col_power_mdi_enabled] =
        lldpctl_atom_get_int(power, lldpctl_k_dot3_power_enabled);
    m_row[col_power_paircontrol_enabled] =
        lldpctl_atom_get_int(power, lldpctl_k_dot3_power_paircontrol);
    m_row[col_power_pairs] = getAtomStr(power, lldpctl_k_dot3_power_pairs);
    m_row[col_power_class] = getAtomStr(power, lldpctl_k_dot3_power_class);
    m_row[col_power_8023at_enabled] =
        (lldpctl_atom_get_int(power, lldpctl_k_dot3_power_type) >
         LLDP_DOT3_POWER_8023AT_OFF);
    m_row[col_power_8023at_power_type] =
        getAtomStr(power, lldpctl_k_dot3_power_type);
    m_row[col_power_8023at_power_source] =
        getAtomStr(power, lldpctl_k_dot3_power_source);
    m_row[col_power_8023at_power_priority] =
        getAtomStr(power, lldpctl_k_dot3_power_priority);
    m_row[col_power_8023at_power_requested] =
        getAtomStr(power, lldpctl_k_dot3_power_requested);
    m_row[col_power_8023at_power_allocated] =
        getAtomStr(power, lldpctl_k_dot3_power_allocated);
  }
  lldpctl_atom_dec_ref(power);

  // Auto-Negotiations
  bool autoneg_supported =
      lldpctl_atom_get_int(m_port, lldpctl_k_port_dot3_autoneg_support);
  m_row[col_port_autoneg_supported] = (autoneg_supported) ? "1" : "0";

  bool autoneg_enabled =
      lldpctl_atom_get_int(m_port, lldpctl_k_port_dot3_autoneg_enabled);
  m_row[col_port_autoneg_enabled] = (autoneg_enabled) ? "1" : "0";

  m_row[col_port_mau_type] = getAtomStr(m_port, lldpctl_k_port_dot3_mautype);

  if (autoneg_supported && autoneg_enabled) {
    long int advertised =
        lldpctl_atom_get_int(m_port, lldpctl_k_port_dot3_autoneg_advertised);

    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_10BASE_T,
                  LLDP_DOT3_LINK_AUTONEG_10BASET_FD,
                  col_port_autoneg_10baset_hd_enabled,
                  col_port_autoneg_10baset_fd_enabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_TX,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD,
                  col_port_autoneg_100basetx_hd_enabled,
                  col_port_autoneg_100basetx_fd_enabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T2,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T2FD,
                  col_port_autoneg_100baset2_hd_enabled,
                  col_port_autoneg_100baset2_fd_enabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                  LLDP_DOT3_LINK_AUTONEG_100BASE_T4,
                  col_port_autoneg_100baset4_hd_enabled,
                  col_port_autoneg_100baset4_fd_enabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_X,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_XFD,
                  col_port_autoneg_1000basex_hd_enabled,
                  col_port_autoneg_1000basex_fd_enabled);
    getPMDAutoNeg(advertised,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_T,
                  LLDP_DOT3_LINK_AUTONEG_1000BASE_TFD,
                  col_port_autoneg_1000baset_hd_enabled,
                  col_port_autoneg_1000baset_fd_enabled);
  }
}

void LLDPNeighbor::getChassis() {
  m_row[col_chassis_index] = getAtomStr(m_chassis, lldpctl_k_chassis_index);
  m_row[col_chassis_id] = getAtomStr(m_chassis, lldpctl_k_chassis_id);
  m_row[col_chassis_id_type] =
      getAtomStr(m_chassis, lldpctl_k_chassis_id_subtype);
  m_row[col_chassis_sysname] = getAtomStr(m_chassis, lldpctl_k_chassis_name);
  m_row[col_chassis_sys_desc] = getAtomStr(m_chassis, lldpctl_k_chassis_descr);

  getChasisCapability(LLDP_CAP_BRIDGE,
                      col_chassis_bridge_capability_available,
                      col_chassis_bridge_capability_enabled);
  getChasisCapability(LLDP_CAP_ROUTER,
                      col_chassis_router_capability_available,
                      col_chassis_router_capability_enabled);
  getChasisCapability(LLDP_CAP_WLAN,
                      col_chassis_wlan_capability_available,
                      col_chassis_wlan_capability_enabled);
  getChasisCapability(LLDP_CAP_REPEATER,
                      col_chassis_repeater_capability_available,
                      col_chassis_repeater_capability_enabled);
  getChasisCapability(LLDP_CAP_TELEPHONE,
                      col_chassis_tel_capability_available,
                      col_chassis_tel_capability_enabled);
  getChasisCapability(LLDP_CAP_DOCSIS,
                      col_chassis_docsis_capability_available,
                      col_chassis_docsis_capability_enabled);
  getChasisCapability(LLDP_CAP_STATION,
                      col_chassis_station_capability_available,
                      col_chassis_station_capability_enabled);
  getChasisCapability(LLDP_CAP_OTHER,
                      col_chassis_other_capability_available,
                      col_chassis_other_capability_enabled);

  lldpctl_atom_t* mgmts = lldpctl_atom_get(m_chassis, lldpctl_k_chassis_mgmt);
  m_row[col_chassis_mgmt_ips] = commaDelimitedStr(mgmts, lldpctl_k_mgmt_ip);
  lldpctl_atom_dec_ref(mgmts);
}

/**
 * getNeighbor retreives all LLDP information of the given neighbor port and
 * chassis.
 *
 * Returns a osquery::Row.
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

  return m_row;
}

QueryData genLLDPNeighbors(QueryContext& context) {
  LLDPNeighbors lldp;
  return lldp.getAllNeighbors();
}
}
}
