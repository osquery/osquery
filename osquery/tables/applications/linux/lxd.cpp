/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <regex>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/asio.hpp>
#include <boost/foreach.hpp>

#if !defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
#error Boost error: Local sockets not available
#endif

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace pt = boost::property_tree;
namespace local = boost::asio::local;
using pt_path = pt::ptree::path_type;

namespace osquery {

/**
 * @brief LXD UNIX domain socket path.
 * Usual suspects: /var/lib/lxd/unix.socket,
 *      /var/snap/lxd/common/lxd/unix.socket
 * If using a different path, specify that path.
 */
FLAG(string,
     lxd_socket,
     "/var/lib/lxd/unix.socket",
     "LXD UNIX domain socket path");

namespace tables {

/**
 * @brief Makes API calls to the LXD UNIX socket.
 *
 * @param uri Relative URI to invoke GET HTTP method.
 * @param tree Property tree where JSON result is stored.
 * @return Status with 0 code on success. Non-negative status with error
 *         message.
 */
Status lxdApi(const std::string& uri, pt::ptree& tree) {
  static const std::regex httpOkRegex("HTTP/1\\.(0|1) 20(0|2) OK\\\r");

  try {
    local::stream_protocol::endpoint ep(FLAGS_lxd_socket);
    local::stream_protocol::iostream stream(ep);
    if (!stream) {
      return Status::failure("Error connecting to LXD sock: " +
                             stream.error().message());
    }

    stream << "GET " << uri
           << " HTTP/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
           << std::flush;
    if (stream.eof()) {
      stream.close();
      return Status::failure("Empty LXD API response for: " + uri);
    }

    std::string str;
    getline(stream, str);

    std::smatch match;
    if (!std::regex_match(str, match, httpOkRegex)) {
      stream.close();
      return Status::failure("Invalid LXD API response for " + uri + ": " +
                             str);
    }

    // Skip empty line between header and body
    while (!stream.eof() && str != "\r") {
      getline(stream, str);
    }

    try {
      pt::read_json(stream, tree);
    } catch (const pt::ptree_error& e) {
      stream.close();
      return Status::failure("Error reading LXD API response for " + uri +
                             ": " + e.what());
    }

    stream.close();
  } catch (const std::exception& e) {
    return Status::failure(std::string("Error calling LXD API: ") + e.what());
  }

  return Status::success();
}

/**
 * @brief Get per-instance state
 */
void getLxdInstanceState(const std::string& url, Row& row) {
  pt::ptree tree;
  Status s = lxdApi(url + "/state", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD instance state" << url << ": " << s.what();
    return;
  }

  try {
    const pt::ptree& node = tree.get_child("metadata");
    row["pid"] = INTEGER(node.get<int>("pid"));
    row["processes"] = INTEGER(node.get<int>("processes"));
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for LXD instance state " << url << ": "
            << e.what();
  }
}

/**
 * @brief Get per-instance metadata
 */
void getLxdInstanceMetadata(const std::string& url, Row& row) {
  pt::ptree tree;
  Status s = lxdApi(url + "/metadata", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD instance metadata" << url << ": " << s.what();
    return;
  }

  try {
    const pt::ptree& node = tree.get_child("metadata").get_child("properties");
    row["description"] = node.get<std::string>("description");
    row["os"] = node.get<std::string>("os");
    row["architecture"] = node.get<std::string>("architecture");
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for LXD instance metadata " << url << ": "
            << e.what();
  }
}

/**
 * @brief Get per-instance info
 */
void getLxdInstance(const std::string& url, QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi(url, tree);
  if (!s.ok()) {
    VLOG(1) << "Error querying LXD instance " << url << ": " << s.what();
    return;
  }

  try {
    const pt::ptree& node = tree.get_child("metadata");
    Row r;
    r["name"] = node.get<std::string>("name");
    r["status"] = node.get<std::string>("status");
    r["stateful"] = node.get<bool>("stateful") ? INTEGER(1) : INTEGER(0);
    r["ephemeral"] = node.get<bool>("ephemeral") ? INTEGER(1) : INTEGER(0);
    r["created_at"] = node.get<std::string>("created_at");
    r["base_image"] = node.get_child("config").get<std::string>(
        pt_path("volatile.base_image", '/'));
    getLxdInstanceMetadata(url, r);
    getLxdInstanceState(url, r);
    results.push_back(r);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for instance " << url << ": " << e.what();
  }
}

/**
 * @brief Calls getLxdInstance() for all LXD instances
 */
void getLxdInstances(QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi("/1.0/containers", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD instances: " << s.what();
    return;
  }

  for (const auto& node : tree.get_child("metadata")) {
    std::string instance_url = node.second.data();
    getLxdInstance(instance_url, results);
  }
}

/**
 * @brief Entry point for lxd_instances table.
 */
QueryData genLxdInstances(QueryContext& context) {
  QueryData results;

  if (context.constraints["name"].exists(EQUALS)) {
    for (const auto& name : context.constraints["name"].getAll(EQUALS)) {
      std::string url = "/1.0/containers/" + name;
      // using /containers instead of /instances for backward compatibility
      getLxdInstance(url, results);
    }
  } else {
    getLxdInstances(results);
  }

  return results;
}

/**
 * @brief Get per-instance config info
 */
void getLxdInstanceConfig(const std::string& name, QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi("/1.0/containers/" + name, tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD instance " << name << ": " << s.what();
    return;
  }

  try {
    for (const auto& node : tree.get_child("metadata").get_child("config")) {
      Row r;
      r["name"] = name;
      r["key"] = node.first;
      r["value"] = node.second.data();
      results.push_back(r);
    }
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for LXD instance " << name << ": "
            << e.what();
  }
}

/**
 * @brief Entry point for lxd_instance_config table.
 */
QueryData genLxdInstanceConfig(QueryContext& context) {
  QueryData results;

  for (const auto& name : context.constraints["name"].getAll(EQUALS)) {
    getLxdInstanceConfig(name, results);
  }

  return results;
}

/**
 * @brief Get per-instance device info
 */
void getLxdInstanceDevice(const std::string& dev_name,
                          const pt::ptree& dev_node,
                          const std::string& instance_name,
                          QueryData& results) {
  try {
    for (const auto& dev_info : dev_node) {
      if (dev_info.first == "type") {
        continue;
      }
      Row r;
      r["name"] = instance_name;
      r["device"] = dev_name;
      r["device_type"] = dev_node.get<std::string>("type", "");
      r["key"] = dev_info.first;
      r["value"] = dev_info.second.data();
      results.push_back(r);
    }
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing device details for LXD instance " << instance_name
            << ": " << e.what();
  }
}

/**
 * @brief Get per-instance devices info
 */
void getLxdInstanceDevices(const std::string& name, QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi("/1.0/containers/" + name, tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD instance " << name << ": " << s.what();
    return;
  }

  try {
    for (const auto& node :
         tree.get_child("metadata").get_child("expanded_devices")) {
      getLxdInstanceDevice(node.first, node.second, name, results);
    }
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for LXD instance " << name << ": "
            << e.what();
  }
}

/**
 * @brief Entry point for lxd_instance_devices table.
 */
QueryData genLxdInstanceDevices(QueryContext& context) {
  QueryData results;

  for (const auto& name : context.constraints["name"].getAll(EQUALS)) {
    getLxdInstanceDevices(name, results);
  }

  return results;
}

/**
 * @brief Get per-image info
 */
void getImage(const std::string& url,
              const std::string& id,
              QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi(url, tree);
  if (!s.ok()) {
    VLOG(1) << "Error querying LXD image " << url << ": " << s.what();
    return;
  }

  try {
    const pt::ptree& node = tree.get_child("metadata");
    Row r;
    r["id"] = id.empty() ? node.get<std::string>("fingerprint") : id;
    r["architecture"] = node.get<std::string>("architecture");
    r["os"] = node.get_child("properties").get<std::string>("os");
    r["release"] = node.get_child("properties").get<std::string>("release");
    r["description"] =
        node.get_child("properties").get<std::string>("description");
    r["filename"] = node.get<std::string>("filename");
    r["size"] = BIGINT(node.get<uint64_t>("size"));
    r["auto_update"] = node.get<bool>("auto_update") ? INTEGER(1) : INTEGER(0);
    r["cached"] = node.get<bool>("cached") ? INTEGER(1) : INTEGER(0);
    r["public"] = node.get<bool>("public") ? INTEGER(1) : INTEGER(0);
    r["created_at"] = node.get<std::string>("created_at");
    r["expires_at"] = node.get<std::string>("expires_at");
    r["uploaded_at"] = node.get<std::string>("uploaded_at");
    r["last_used_at"] = node.get<std::string>("last_used_at");
    r["update_source_server"] =
        node.get_child("update_source").get<std::string>("server");
    r["update_source_protocol"] =
        node.get_child("update_source").get<std::string>("protocol");
    r["update_source_certificate"] =
        node.get_child("update_source").get<std::string>("certificate");
    r["update_source_alias"] =
        node.get_child("update_source").get<std::string>("alias");

    std::string aliases;
    for (const auto& alias : node.get_child("aliases")) {
      if (!aliases.empty()) {
        aliases.append(",");
      }
      aliases.append(alias.second.get<std::string>("name"));
    }
    r["aliases"] = aliases;

    results.push_back(r);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for image " << url << ": " << e.what();
  }
}

/**
 * @brief Calls getImage() for all LXD images
 */
void getImages(QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi("/1.0/images", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD images: " << s.what();
    return;
  }

  for (const auto& node : tree.get_child("metadata")) {
    std::string image_url = node.second.data();
    getImage(image_url, std::string(), results);
  }
}

/**
 * @brief Entry point for lxd_images table.
 */
QueryData genLxdImages(QueryContext& context) {
  QueryData results;

  if (context.constraints["id"].exists(EQUALS)) {
    for (const auto& id : context.constraints["id"].getAll(EQUALS)) {
      std::string url = "/1.0/images/" + id;
      getImage(url, id, results);
    }
  } else {
    getImages(results);
  }

  return results;
}

/**
 * @brief Get per-certificate info
 */
void getLxdCert(const std::string& url, QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi(url, tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD certificate " << url << ": " << s.what();
    return;
  }

  try {
    const pt::ptree& node = tree.get_child("metadata");
    Row r;
    r["name"] = node.get<std::string>("name", "");
    r["type"] = node.get<std::string>("type", "");
    r["fingerprint"] = node.get<std::string>("fingerprint", "");
    r["certificate"] = node.get<std::string>("certificate", "");
    results.push_back(r);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for certificate " << url << ": "
            << e.what();
  }
}

/**
 * @brief Entry point for lxd_certificates table.
 */
QueryData genLxdCerts(QueryContext& context) {
  QueryData results;

  pt::ptree tree;
  Status s = lxdApi("/1.0/certificates", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD certificates: " << s.what();
    return results;
  }

  for (const auto& node : tree.get_child("metadata")) {
    std::string cert_url = node.second.data();
    getLxdCert(cert_url, results);
  }

  return results;
}

/**
 * @brief Get per-network info additional
 */
void getLxdNetworkState(const std::string& url, Row& row) {
  pt::ptree tree;
  Status s = lxdApi(url + "/state", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD network state" << url << ": " << s.what();
    return;
  }
  try {
    const pt::ptree& node = tree.get_child("metadata");
    const pt::ptree& counter_node = node.get_child("counters");
    row["bytes_received"] =
        BIGINT(counter_node.get<uint64_t>("bytes_received"));
    row["bytes_sent"] = BIGINT(counter_node.get<uint64_t>("bytes_sent"));
    row["packets_received"] =
        BIGINT(counter_node.get<uint64_t>("packets_received"));
    row["packets_sent"] = BIGINT(counter_node.get<uint64_t>("packets_sent"));
    row["hwaddr"] = node.get<std::string>("hwaddr");
    row["state"] = node.get<std::string>("state");
    row["mtu"] = INTEGER(node.get<int>("mtu"));
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for network state " << url << ": "
            << e.what();
  }
}

/**
 * @brief Get network user info
 */
void getLxdNetworkUsers(const pt::ptree& users_node, Row& row) {
  try {
    std::string users;
    for (const auto& node : users_node) {
      if (!users.empty()) {
        users.append(",");
      }
      std::string user = node.second.data();
      if (boost::starts_with(user, "/1.0/containers/")) {
        user.erase(0, 16);
      } else if (boost::starts_with(user, "/1.0/instances/")) {
        user.erase(0, 15);
      }
      users.append(user);
    }
    row["used_by"] = users;
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error getting network user details: " << e.what();
  }
}

/**
 * @brief Get per-network info
 */
void getLxdNetwork(const std::string& url, QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi(url, tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD network " << url << ": " << s.what();
    return;
  }

  try {
    const pt::ptree& node = tree.get_child("metadata");
    const pt::ptree& config_node = node.get_child("config");
    Row r;
    r["name"] = node.get<std::string>("name");
    r["type"] = node.get<std::string>("type");
    r["managed"] = node.get<bool>("managed") ? INTEGER(1) : INTEGER(0);
    r["ipv4_address"] =
        config_node.get<std::string>(pt_path("ipv4.address", '/'), "");
    r["ipv6_address"] =
        config_node.get<std::string>(pt_path("ipv6.address", '/'), "");
    getLxdNetworkUsers(node.get_child("used_by"), r);
    getLxdNetworkState(url, r);
    results.push_back(r);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for network " << url << ": " << e.what();
  }
}

/**
 * @brief Entry point for lxd_networks table.
 */
QueryData genLxdNetworks(QueryContext& context) {
  QueryData results;

  pt::ptree tree;
  Status s = lxdApi("/1.0/networks", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD networks: " << s.what();
    return results;
  }

  for (const auto& node : tree.get_child("metadata")) {
    std::string nw_url = node.second.data();
    getLxdNetwork(nw_url, results);
  }

  return results;
}

/**
 * @brief Entry point for lxd_cluster table.
 */
QueryData genLxdCluster(QueryContext& context) {
  QueryData results;

  pt::ptree tree;
  Status s = lxdApi("/1.0/cluster", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD cluster: " << s.what();
    return results;
  }

  try {
    const auto& node = tree.get_child("metadata");
    Row r;
    r["server_name"] = node.get<std::string>("server_name");
    r["enabled"] = node.get<bool>("enabled") ? INTEGER(1) : INTEGER(0);
    for (const auto& member_node : node.get_child("member_config")) {
      r["member_config_entity"] = member_node.second.get<std::string>("entity");
      r["member_config_name"] = member_node.second.get<std::string>("name");
      r["member_config_key"] = member_node.second.get<std::string>("key");
      r["member_config_value"] =
          member_node.second.get<std::string>("value", "");
      r["member_config_description"] =
          member_node.second.get<std::string>("description");
    }
    results.push_back(r);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for LXD cluster: " << e.what();
  }

  return results;
}

/**
 * @brief Get per-cluster-member info
 */
void getLxdClusterMember(const std::string& url, QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi(url, tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD cluster member " << url << ": " << s.what();
    return;
  }

  try {
    const pt::ptree& node = tree.get_child("metadata");
    Row r;
    r["server_name"] = node.get<std::string>("server_name");
    r["url"] = node.get<std::string>("url");
    r["database"] = node.get<bool>("database") ? INTEGER(1) : INTEGER(0);
    r["status"] = node.get<std::string>("status");
    r["message"] = node.get<std::string>("message");
    results.push_back(r);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for cluster member " << url << ": "
            << e.what();
  }
}

/**
 * @brief Entry point for lxd_cluster_members table.
 */
QueryData genLxdClusterMembers(QueryContext& context) {
  QueryData results;

  pt::ptree tree;
  Status s = lxdApi("/1.0/cluster/members", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD cluster members: " << s.what();
    return results;
  }

  for (const auto& node : tree.get_child("metadata")) {
    std::string url = node.second.data();
    getLxdClusterMember(url, results);
  }

  return results;
}

/**
 * @brief Get per-storage-pool resources
 */
void getLxdStoragePoolResources(const std::string& url, Row& row) {
  pt::ptree tree;
  Status s = lxdApi(url + "/resources", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD storage pool resources" << url << ": "
            << s.what();
    return;
  }

  try {
    const pt::ptree& node = tree.get_child("metadata");
    row["space_used"] = BIGINT(node.get_child("space").get<uint64_t>("used"));
    row["space_total"] = BIGINT(node.get_child("space").get<uint64_t>("total"));
    row["inodes_used"] = BIGINT(node.get_child("inodes").get<uint64_t>("used"));
    row["inodes_total"] =
        BIGINT(node.get_child("inodes").get<uint64_t>("total"));
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for storage pool resources " << url
            << ": " << e.what();
  }
}

/**
 * @brief Get per-storage-pool info
 */
void getLxdStoragePool(const std::string& url, QueryData& results) {
  pt::ptree tree;
  Status s = lxdApi(url, tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD storage pool " << url << ": " << s.what();
    return;
  }

  try {
    const pt::ptree& node = tree.get_child("metadata");
    const pt::ptree& config_node = node.get_child("config");
    Row r;
    r["name"] = node.get<std::string>("name");
    r["driver"] = node.get<std::string>("driver");
    r["source"] = config_node.get<std::string>("source", "");
    r["size"] = config_node.get<std::string>("size", "");
    getLxdStoragePoolResources(url, r);
    results.push_back(r);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing details for storage pool " << url << ": "
            << e.what();
  }
}

/**
 * @brief Entry point for lxd_storage_pools table.
 */
QueryData genLxdStoragePools(QueryContext& context) {
  QueryData results;

  pt::ptree tree;
  Status s = lxdApi("/1.0/storage-pools", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting LXD storage pools: " << s.what();
    return results;
  }

  for (const auto& node : tree.get_child("metadata")) {
    std::string url = node.second.data();
    getLxdStoragePool(url, results);
  }

  return results;
}

} // namespace tables
} // namespace osquery
