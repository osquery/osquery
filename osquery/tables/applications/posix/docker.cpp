/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <regex>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/property_tree/json_parser.hpp>

// TODO(5591) Remove this when addressed by Boost's ASIO config.
// https://www.boost.org/doc/libs/1_67_0/boost/asio/detail/config.hpp
// Standard library support for std::string_view.
#define BOOST_ASIO_DISABLE_STD_STRING_VIEW 1

#include <boost/asio.hpp>
#include <boost/foreach.hpp>

#if !defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
#error Boost error: Local sockets not available
#endif

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/json/json.h>

// When building on linux, the extended schema of docker_containers will
// add some additional columns to support user namespaces
#ifdef __linux__
#include <osquery/filesystem/linux/proc.h>
#endif

namespace pt = boost::property_tree;
namespace local = boost::asio::local;

namespace osquery {

/**
 * @brief Docker UNIX domain socket path.
 *
 * By default docker creates UNIX domain socket at /var/run/docker.sock. If
 * docker domain is configured to use a different path specify that path.
 */
FLAG(string,
     docker_socket,
     "/var/run/docker.sock",
     "Docker UNIX domain socket path");

namespace tables {

/**
 * @brief Makes API calls to the docker UNIX socket.
 *
 * @param uri Relative URI to invoke GET HTTP method.
 * @param tree Property tree where JSON result is stored.
 * @return Status with 0 code on success. Non-negative status with error
 *         message.
 */
Status dockerApi(const std::string& uri, pt::ptree& tree) {
  static const std::regex httpOkRegex("HTTP/1\\.(0|1) 200 OK\\\r");

  try {
    local::stream_protocol::endpoint ep(FLAGS_docker_socket);
    local::stream_protocol::iostream stream(ep);
    if (!stream) {
      return Status(
          1, "Error connecting to docker sock: " + stream.error().message());
    }

    // Since keep-alive connections are not used, use HTTP/1.0
    stream << "GET " << uri
           << " HTTP/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
           << std::flush;
    if (stream.eof()) {
      stream.close();
      return Status(1, "Empty docker API response for: " + uri);
    }

    // All status responses are expected to be 200
    std::string str;
    getline(stream, str);

    std::smatch match;
    if (!std::regex_match(str, match, httpOkRegex)) {
      stream.close();
      return Status(1, "Invalid docker API response for " + uri + ": " + str);
    }

    // Skip empty line between header and body
    while (!stream.eof() && str != "\r") {
      getline(stream, str);
    }

    try {
      pt::read_json(stream, tree);
    } catch (const pt::ptree_error& e) {
      stream.close();
      return Status(
          1, "Error reading docker API response for " + uri + ": " + e.what());
    }

    stream.close();
  } catch (const std::exception& e) {
    return Status(1, std::string("Error calling docker API: ") + e.what());
  }

  return Status(0);
}

/**
 * @brief Entry point for docker_version table.
 */
QueryData genVersion(QueryContext& context) {
  QueryData results;
  pt::ptree tree;
  Status s = dockerApi("/version", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting docker version: " << s.what();
    return results;
  }

  Row r;
  r["version"] = tree.get<std::string>("Version", "");
  r["api_version"] = tree.get<std::string>("ApiVersion", "");
  r["min_api_version"] = tree.get<std::string>("MinAPIVersion", "");
  r["git_commit"] = tree.get<std::string>("GitCommit", "");
  r["go_version"] = tree.get<std::string>("GoVersion", "");
  r["os"] = tree.get<std::string>("Os", "");
  r["arch"] = tree.get<std::string>("Arch", "");
  r["kernel_version"] = tree.get<std::string>("KernelVersion", "");
  r["build_time"] = tree.get<std::string>("BuildTime", "");
  results.push_back(r);

  return results;
}

/**
 * @brief Entry point for docker_info table.
 */
QueryData genInfo(QueryContext& context) {
  QueryData results;
  pt::ptree tree;
  Status s = dockerApi("/info", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting docker info: " << s.what();
    return results;
  }

  Row r;
  r["id"] = tree.get<std::string>("ID", "");
  r["containers"] = INTEGER(tree.get<int>("Containers", 0));
  r["containers_running"] = INTEGER(tree.get<int>("ContainersRunning", 0));
  r["containers_paused"] = INTEGER(tree.get<int>("ContainersPaused", 0));
  r["containers_stopped"] = INTEGER(tree.get<int>("ContainersStopped", 0));
  r["images"] = INTEGER(tree.get<int>("Images", 0));
  r["storage_driver"] = tree.get<std::string>("Driver", "");
  r["memory_limit"] =
      (tree.get<bool>("MemoryLimit", false) ? INTEGER(1) : INTEGER(0));
  r["swap_limit"] =
      (tree.get<bool>("SwapLimit", false) ? INTEGER(1) : INTEGER(0));
  r["kernel_memory"] =
      (tree.get<bool>("KernelMemory", false) ? INTEGER(1) : INTEGER(0));
  r["cpu_cfs_period"] =
      (tree.get<bool>("CpuCfsPeriod", false) ? INTEGER(1) : INTEGER(0));
  r["cpu_cfs_quota"] =
      (tree.get<bool>("CpuCfsQuota", false) ? INTEGER(1) : INTEGER(0));
  r["cpu_shares"] =
      (tree.get<bool>("CPUShares", false) ? INTEGER(1) : INTEGER(0));
  r["cpu_set"] = (tree.get<bool>("CPUSet", false) ? INTEGER(1) : INTEGER(0));
  r["ipv4_forwarding"] =
      (tree.get<bool>("IPv4Forwarding", false) ? INTEGER(1) : INTEGER(0));
  r["bridge_nf_iptables"] =
      (tree.get<bool>("BridgeNfIptables", false) ? INTEGER(1) : INTEGER(0));
  r["bridge_nf_ip6tables"] =
      (tree.get<bool>("BridgeNfIp6tables", false) ? INTEGER(1) : INTEGER(0));
  r["oom_kill_disable"] =
      (tree.get<bool>("OomKillDisable", false) ? INTEGER(1) : INTEGER(0));
  r["logging_driver"] = tree.get<std::string>("LoggingDriver", "");
  r["cgroup_driver"] = tree.get<std::string>("CgroupDriver", "");
  r["kernel_version"] = tree.get<std::string>("KernelVersion", "");
  r["os"] = tree.get<std::string>("OperatingSystem", "");
  r["os_type"] = tree.get<std::string>("OSType", "");
  r["architecture"] = tree.get<std::string>("Architecture", "");
  r["cpus"] = INTEGER(tree.get<int>("NCPU", 0));
  r["memory"] = BIGINT(tree.get<uint64_t>("MemTotal", 0));
  r["http_proxy"] = tree.get<std::string>("HttpProxy", "");
  r["https_proxy"] = tree.get<std::string>("HttpsProxy", "");
  r["no_proxy"] = tree.get<std::string>("NoProxy", "");
  r["name"] = tree.get<std::string>("Name", "");
  r["server_version"] = tree.get<std::string>("ServerVersion", "");
  r["root_dir"] = tree.get<std::string>("DockerRootDir", "");
  results.push_back(r);

  return results;
}

/**
 * @brief Utility method to check if specified string is SHA-256 hash or a
 * substring.
 */
bool checkConstraintValue(const std::string& str) {
  if (str.length() > 64) {
    VLOG(1) << "Constraint value is too long. Ignoring: " << str;
    return false;
  }
  for (size_t i = 0; i < str.length(); i++) {
    if (!isxdigit(str.at(i))) {
      VLOG(1) << "Constraint value is not SHA-256 hash. Ignoring: " << str;
      return false;
    }
  }
  return true;
}

/**
 * @brief Utility method to create query arguments for docker API URI.
 *
 * @param context Query context which contains SQL constraint.
 * @param key Constraint column to look for (eg: "id", "name").
 * @param query Placeholder for returning query string.
 * @param set Set for returning constraint values for specified key.
 * @param add_all Whether to add "all=1" to query string or not.
 */
void getQuery(QueryContext& context,
              const std::string& key,
              std::string& query,
              std::set<std::string>& set,
              bool add_all) {
  if (!context.constraints[key].exists(EQUALS)) {
    return;
  }

  std::string key_str;
  for (const auto& item : context.constraints[key].getAll(EQUALS)) {
    if (!checkConstraintValue(item)) {
      continue;
    }
    if (!key_str.empty()) {
      key_str.append("%2C"); // comma
    }
    key_str.append("%22").append(item).append("%22%3Atrue"); // "item":true
    set.insert(item);
  }

  query.append("?");
  if (add_all) {
    query.append("all=1&");
  }
  // filters={"key": {"item1":true, "item2":true, ...}}
  query.append("filters=%7B%22")
      .append(key)
      .append("%22%3A%7B")
      .append(key_str)
      .append("%7D%7D");
}

/**
 * @brief Utility method to get value for specified key.
 *
 * Docker supports querying primary columns by prefix. This is preserved when
 * querying thought OSQuery.
 *
 * For example the following should return same result as long as there is only
 * one container with "id" that starts with "12345678":
 *   SELECT * FROM docker_containers WHERE id = '1234567890abcdef'
 *   SELECT * FROM docker_containers WHERE id = '12345678'
 *
 * @param tree Property tree response from docker.
 * @param set Set that might contain prefix values.
 * @param key Key to look for in the property tree.
 */
std::string getValue(const pt::ptree& tree,
                     const std::set<std::string>& set,
                     const std::string& key) {
  std::string value = tree.get<std::string>(key, "");
  if (boost::starts_with(value, "sha256:")) {
    value.erase(0, 7);
  }
  if (set.empty()) {
    return value; // Return value from tree, if set is empty
  }

  for (const auto& entry : set) {
    if (boost::starts_with(value, entry)) {
      return entry; // If entry from set is prefix of value from tree, return
    }
  }

  return value;
}

/**
 * @brief Utility method to retrieve labels for docker objects.
 *
 * @param context Query context.
 * @param type Docker object type (container, volume, network).
 * @param column Column to look for in context (id, name).
 * @param primary_key Primary key field name to look for in property tree (Id,
 * Name).
 * @param url URI to invoke (without query string).
 * @param path Path in the tree to iterate. Can be empty. Volumes is a nested
 * array.
 * @param add_all Whether to append "all=1" to query string or not.
 */
QueryData getLabels(QueryContext& context,
                    const std::string& type,
                    const std::string& column,
                    const std::string& primary_key,
                    const std::string& url,
                    const std::string& path,
                    bool filter,
                    bool add_all) {
  std::string query;
  std::set<std::string> items;
  getQuery(context, column, query, items, add_all);

  QueryData results;
  pt::ptree tree;
  const std::string& url_qs = filter ? (url + query) : url;
  Status s = dockerApi(url_qs, tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting docker " << type << ": " << s.what();
    return results;
  }

  try {
    const pt::ptree& array = path.empty() ? tree : tree.get_child(path);
    for (const auto& entry : array) {
      const pt::ptree& node = entry.second;
      const std::string& pk = getValue(node, items, primary_key);

      for (const auto& label : node.get_child("Labels")) {
        Row r;
        r[column] = pk;
        r["key"] = label.first.data();
        r["value"] = label.second.data();
        results.push_back(r);
      }
    }
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error getting docker " << type << " labels "
            << ": " << e.what();
  }

  return results;
}

/**
 * @brief Utility method to get containers tree.
 */
Status getContainers(QueryContext& context,
                     std::set<std::string>& ids,
                     pt::ptree& containers) {
  std::string query;
  getQuery(context, "id", query, ids, true);

  Status s = dockerApi("/containers/json" + query, containers);
  if (!s.ok()) {
    VLOG(1) << "Error getting docker containers: " << s.what();
    return s;
  }
  return Status(0);
}

/**
 * @brief Entry point for docker_containers table.
 */
QueryData genContainers(QueryContext& context) {
  QueryData results;
  std::set<std::string> ids;
  pt::ptree containers;
  auto s = getContainers(context, ids, containers);
  if (!s.ok()) {
    return results;
  }

  for (const auto& entry : containers) {
    const pt::ptree& container = entry.second;
    Row r;
    r["id"] = getValue(container, ids, "Id");
    if (container.count("Names") > 0) {
      for (const auto& name : container.get_child("Names")) {
        r["name"] = name.second.data();
        break;
      }
    }

    r["image_id"] = container.get<std::string>("ImageID", "");
    if (boost::starts_with(r["image_id"], "sha256:")) {
      r["image_id"].erase(0, 7);
    }
    r["image"] = container.get<std::string>("Image", "");
    r["command"] = container.get<std::string>("Command", "");
    r["created"] = BIGINT(container.get<uint64_t>("Created", 0));
    r["state"] = container.get<std::string>("State", "");
    r["status"] = container.get<std::string>("Status", "");

    pt::ptree container_details;
    s = dockerApi("/containers/" + r["id"] + "/json?stream=false",
                  container_details);
    if (s.ok()) {
      r["pid"] =
          BIGINT(container_details.get_child("State").get<pid_t>("Pid", -1));
      r["started_at"] = container_details.get_child("State").get<std::string>(
          "StartedAt", "");
      r["finished_at"] = container_details.get_child("State").get<std::string>(
          "FinishedAt", "");
      r["privileged"] = container_details.get_child("HostConfig")
                                .get<bool>("Privileged", false)
                            ? INTEGER(1)
                            : INTEGER(0);
      r["readonly_rootfs"] = container_details.get_child("HostConfig")
                                     .get<bool>("ReadonlyRootfs", false)
                                 ? INTEGER(1)
                                 : INTEGER(0);
      r["path"] = container_details.get<std::string>("Path", "");

      std::vector<std::string> entry_pts;
      for (const auto& ent_pt :
           container_details.get_child("Config.Entrypoint")) {
        entry_pts.push_back(ent_pt.second.data());
      }
      r["config_entrypoint"] = osquery::join(entry_pts, ", ");

      std::vector<std::string> sec_opts;
      for (const auto& sec_opt :
           container_details.get_child("HostConfig.SecurityOpt")) {
        sec_opts.push_back(sec_opt.second.data());
      }
      r["security_options"] = osquery::join(sec_opts, ", ");

      std::vector<std::string> env_vars;
      for (const auto& env_var : container_details.get_child("Config.Env")) {
        env_vars.push_back(env_var.second.data());
      }
      r["env_variables"] = osquery::join(env_vars, ", ");

    } else {
      VLOG(1) << "Failed to retrieve the inspect data for container "
              << r["id"];
    }

// When building on linux, the extended schema of docker_containers will
// add some additional columns to support user namespaces
#ifdef __linux__
    if (r["pid"] != "-1") {
      ProcessNamespaceList namespace_list;
      s = procGetProcessNamespaces(r["pid"], namespace_list);
      if (s.ok()) {
        for (const auto& pair : namespace_list) {
          r[pair.first + "_namespace"] = std::to_string(pair.second);
        }
      } else {
        VLOG(1) << "Failed to retrieve the namespace list for container "
                << r["id"];
      }
    }
#endif

    results.push_back(r);
  }

  return results;
}

/**
 * @brief Entry point for docker_container_labels table.
 */
QueryData genContainerLabels(QueryContext& context) {
  return getLabels(context,
                   "container", // Docker object type
                   "id", // Look for "id" column in context
                   "Id", // Container primary key is "Id"
                   "/containers/json", // All containers URL
                   "", // Container array is at top level
                   true, // Supports "filters" in query string
                   true); // Supports "all" in query string
}

/**
 * @brief Entry point for docker_container_mounts table.
 */
QueryData genContainerMounts(QueryContext& context) {
  QueryData results;
  std::set<std::string> ids;
  pt::ptree containers;
  Status s = getContainers(context, ids, containers);
  if (!s.ok()) {
    return results;
  }

  for (const auto& entry : containers) {
    const pt::ptree& container = entry.second;
    try {
      for (const auto& node : container.get_child("Mounts")) {
        const pt::ptree& mount = node.second;
        Row r;
        r["id"] = getValue(container, ids, "Id");
        r["type"] = mount.get<std::string>("Type", "");
        r["name"] = mount.get<std::string>("Name", "");
        r["source"] = mount.get<std::string>("Source", "");
        r["destination"] = mount.get<std::string>("Destination", "");
        r["driver"] = mount.get<std::string>("Driver", "");
        r["mode"] = mount.get<std::string>("Mode", "");
        r["rw"] = (mount.get<bool>("RW", false) ? INTEGER(1) : INTEGER(0));
        r["propagation"] = mount.get<std::string>("Propagation", "");
        results.push_back(r);
      }
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error getting docker container mounts " << e.what();
    }
  }

  return results;
}

/**
 * @brief Entry point for docker_container_networks table.
 */
QueryData genContainerNetworks(QueryContext& context) {
  QueryData results;
  std::set<std::string> ids;
  pt::ptree containers;
  Status s = getContainers(context, ids, containers);
  if (!s.ok()) {
    return results;
  }

  for (const auto& entry : containers) {
    const pt::ptree& container = entry.second;
    try {
      for (const auto& node : container.get_child("NetworkSettings.Networks")) {
        const pt::ptree& network = node.second;
        Row r;
        r["id"] = getValue(container, ids, "Id");
        r["name"] = node.first.data();
        r["network_id"] = network.get<std::string>("NetworkID", "");
        r["endpoint_id"] = network.get<std::string>("EndpointID", "");
        r["gateway"] = network.get<std::string>("Gateway", "");
        r["ip_address"] = network.get<std::string>("IPAddress", "");
        r["ip_prefix_len"] = INTEGER(network.get<int>("IPPrefixLen", 0));
        r["ipv6_gateway"] = network.get<std::string>("IPv6Gateway", "");
        r["ipv6_address"] = network.get<std::string>("GlobalIPv6Address", "");
        r["ipv6_prefix_len"] =
            INTEGER(network.get<int>("GlobalIPv6PrefixLen", 0));
        r["mac_address"] = network.get<std::string>("MacAddress", "");
        results.push_back(r);
      }
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error getting docker container networks " << e.what();
    }
  }

  return results;
}

/**
 * @brief Entry point for docker_container_ports table.
 */
QueryData genContainerPorts(QueryContext& context) {
  QueryData results;
  std::set<std::string> ids;
  pt::ptree containers;
  Status s = getContainers(context, ids, containers);
  if (!s.ok()) {
    return results;
  }

  for (const auto& entry : containers) {
    const pt::ptree& container = entry.second;
    try {
      for (const auto& node : container.get_child("Ports")) {
        const pt::ptree& details = node.second;
        Row r;
        r["id"] = getValue(container, ids, "Id");
        r["type"] = details.get<std::string>("Type", "");
        r["port"] = INTEGER(details.get<int>("PrivatePort", 0));
        r["host_ip"] = details.get<std::string>("IP", "");
        r["host_port"] = INTEGER(details.get<int>("PublicPort", 0));
        results.push_back(r);
      }
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error getting docker container ports " << e.what();
    }
  }

  return results;
}

/**
 * @brief Entry point for docker_container_processes table.
 */
QueryData genContainerProcesses(QueryContext& context) {
  QueryData results;
  std::string ps_args;

  for (const auto& id : context.constraints["id"].getAll(EQUALS)) {
    if (!checkConstraintValue(id)) {
      continue;
    }

    pt::ptree container;

    if (isPlatform(PlatformType::TYPE_OSX)) {
      // osx: 19 fields
      // currently OS X Docker API will only return
      // "PID","USER","TIME","COMMAND" fields
      ps_args =
          "pid,state,uid,gid,svuid,svgid,rss,vsz,etime,ppid,pgid,wq,nice,user,"
          "time,pcpu,pmem,comm,command";
    } else if (isPlatform(PlatformType::TYPE_LINUX)) {
      // linux: 21 fields
      ps_args =
          "pid,state,uid,gid,euid,egid,suid,sgid,rss,vsz,etime,ppid,pgrp,nlwp,"
          "nice,user,time,pcpu,pmem,comm,cmd";
    } else {
      continue;
    }

    auto s = dockerApi("/containers/" + id + "/top?ps_args=axwwo%20" + ps_args,
                       container);

    if (!s.ok()) {
      VLOG(1) << "Error getting docker container " << id << ": " << s.what();
      continue;
    }

    try {
      for (const auto& processes : container.get_child("Processes")) {
        std::vector<std::string> vector;
        for (const auto& v : processes.second) {
          vector.push_back(v.second.data());
        }

        Row r;
        r["id"] = id;
        r["pid"] = BIGINT(vector.at(0));
        r["wired_size"] = BIGINT(0); // No support for unpagable counters
        if (isPlatform(PlatformType::TYPE_OSX) && vector.size() == 4) {
          r["uid"] = BIGINT(vector.at(1));
          r["time"] = vector.at(2);
          r["cmdline"] = vector.at(3);
        } else if (isPlatform(PlatformType::TYPE_LINUX) &&
                   vector.size() == 21) {
          r["state"] = vector.at(1);
          r["uid"] = BIGINT(vector.at(2));
          r["gid"] = BIGINT(vector.at(3));
          r["euid"] = BIGINT(vector.at(4));
          r["egid"] = BIGINT(vector.at(5));
          r["suid"] = BIGINT(vector.at(6));
          r["sgid"] = BIGINT(vector.at(7));
          r["resident_size"] = BIGINT(vector.at(8) + "000");
          r["total_size"] = BIGINT(vector.at(9) + "000");
          r["start_time"] = BIGINT(vector.at(10));
          r["parent"] = BIGINT(vector.at(11));
          r["pgroup"] = BIGINT(vector.at(12));
          r["threads"] = INTEGER(vector.at(13));
          r["nice"] = INTEGER(vector.at(14));
          r["user"] = vector.at(15);
          r["time"] = vector.at(16);
          r["cpu"] = DOUBLE(vector.at(17));
          r["mem"] = DOUBLE(vector.at(18));
          r["name"] = vector.at(19);
          r["cmdline"] = vector.at(20);
        } else {
          continue;
        }

        results.push_back(r);
      }
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error getting docker container processes " << id << ": "
              << e.what();
    }
  }

  return results;
}

/**
 * @brief Parses provided date string and return time in seconds since epoch.
 *
 * @param iso_8601 Date string in format: 2017-05-01T16:08:43
 * @param local Whether the time is in local timezone or UTC.
 * @return Seconds since epoch.
 */
long getUnixTime(const std::string& iso_8601, bool local) {
  // Difference in seconds between local and UTC time zones
  static const std::time_t now = std::time(nullptr);
  static const long diff =
      std::mktime(std::gmtime(&now)) - std::mktime(std::localtime(&now));

  if (iso_8601.empty()) {
    return 0L;
  }

  std::tm tm = {};
  std::istringstream ss(iso_8601);
  ss >> std::get_time(&tm, "%Y-%m-%dT%T");
  if (ss.fail()) {
    VLOG(1) << "Failed to parse date: " << iso_8601;
    return 0L;
  }

  return local ? std::mktime(&tm) : (std::mktime(&tm) - diff);
}

/**
 * @brief Parses nano-seconds out of specified date strings and returns
 *        difference.
 *
 * @param iso1 Date string in format: 2017-05-01T16:08:43.661631023Z
 * @param iso2 Date string in format: 2017-05-01T16:08:43.661631023Z
 * @return Nano-seconds difference.
 */
long diffNanos(const std::string& iso1, const std::string& iso2) {
  if (iso1.empty() || iso2.empty()) {
    return 0L;
  }

  std::size_t pos1 = iso1.find('.');
  std::size_t pos2 = iso2.find('.');
  if (pos1 == std::string::npos || pos2 == std::string::npos) {
    VLOG(1) << "Failed to parse dates: " << iso1 << " and " << iso2;
    return 0L;
  }

  try {
    return std::stol(iso1.substr(pos1 + 1), nullptr, 10) -
           std::stol(iso2.substr(pos2 + 1), nullptr, 10);
  } catch (std::out_of_range& e) {
    VLOG(1) << "Failed to parse nano seconds in: " << iso1 << " and " << iso2;
    return 0L;
  }
}

/**
 * @brief Utility method to get cumulative value for specified "op" from
 *        child node in provided "tree".
 *
 * @param tree Tree to iterate.
 * @param op IO operation to look for in the child nodes.
 * @return Cumulative value for type "op".
 */
std::string getIOBytes(const pt::ptree& tree, const std::string& op) {
  uint64_t value = 0;
  for (const auto& entry : tree) {
    const pt::ptree& node = entry.second;
    if (node.get<std::string>("op", "") == op) {
      value += node.get<uint64_t>("value", 0);
    }
  }

  return BIGINT(value);
}

/**
 * @brief Utility method to get cumulative value for specified "key" from
 *        child node in provided "tree".
 *
 * @param tree Tree to iterate.
 * @param key Key to look for in the child nodes.
 * @return Cumulative value for "key".
 */
std::string getNetworkBytes(const pt::ptree& tree, const std::string& key) {
  uint64_t value = 0;
  for (const auto& node : tree) {
    value += node.second.get<uint64_t>(key, 0);
  }

  return BIGINT(value);
}

/**
 * @brief Entry point for docker_container_stats table.
 */
QueryData genContainerStats(QueryContext& context) {
  QueryData results;
  for (const auto& id : context.constraints["id"].getAll(EQUALS)) {
    if (!checkConstraintValue(id)) {
      continue;
    }

    pt::ptree container;
    Status s =
        dockerApi("/containers/" + id + "/stats?stream=false", container);
    if (!s.ok()) {
      VLOG(1) << "Error getting docker container " << id << ": " << s.what();
      continue;
    }

    try {
      Row r;
      r["id"] = id;
      r["name"] = container.get<std::string>("name", "");
      r["pids"] = container.get<int>("pids_stats.current", 0);
      const std::string& read = container.get<std::string>("read", "");
      long read_unix_time = getUnixTime(read, false);
      r["read"] = BIGINT(read_unix_time);
      const std::string& preread = container.get<std::string>("preread", "");
      long preread_unix_time = getUnixTime(preread, false);
      r["preread"] = BIGINT(preread_unix_time);
      long intervalNanos = ((read_unix_time - preread_unix_time) * 1000000000) +
                           diffNanos(read, preread);
      r["interval"] = BIGINT(intervalNanos);
      r["disk_read"] = getIOBytes(
          container.get_child("blkio_stats.io_service_bytes_recursive"),
          "Read");
      r["disk_write"] = getIOBytes(
          container.get_child("blkio_stats.io_service_bytes_recursive"),
          "Write");
      r["num_procs"] = INTEGER(container.get<int>("num_procs", 0));
      r["cpu_total_usage"] =
          BIGINT(container.get<uint64_t>("cpu_stats.cpu_usage.total_usage", 0));
      r["cpu_kernelmode_usage"] = BIGINT(container.get<uint64_t>(
          "cpu_stats.cpu_usage.usage_in_kernelmode", 0));
      r["cpu_usermode_usage"] = BIGINT(
          container.get<uint64_t>("cpu_stats.cpu_usage.usage_in_usermode", 0));
      r["system_cpu_usage"] =
          BIGINT(container.get<uint64_t>("cpu_stats.system_cpu_usage", 0));
      r["online_cpus"] =
          INTEGER(container.get<uint64_t>("cpu_stats.online_cpus", 0));
      r["pre_cpu_total_usage"] = BIGINT(
          container.get<uint64_t>("precpu_stats.cpu_usage.total_usage", 0));
      r["pre_cpu_kernelmode_usage"] = BIGINT(container.get<uint64_t>(
          "precpu_stats.cpu_usage.usage_in_kernelmode", 0));
      r["pre_cpu_usermode_usage"] = BIGINT(container.get<uint64_t>(
          "precpu_stats.cpu_usage.usage_in_usermode", 0));
      r["pre_system_cpu_usage"] =
          BIGINT(container.get<uint64_t>("precpu_stats.system_cpu_usage", 0));
      r["pre_online_cpus"] =
          INTEGER(container.get<uint64_t>("precpu_stats.online_cpus", 0));
      r["memory_usage"] =
          BIGINT(container.get<uint64_t>("memory_stats.usage", 0));
      r["memory_max_usage"] =
          BIGINT(container.get<uint64_t>("memory_stats.max_usage", 0));
      r["memory_limit"] =
          BIGINT(container.get<uint64_t>("memory_stats.limit", 0));
      r["network_rx_bytes"] =
          getNetworkBytes(container.get_child("networks"), "rx_bytes");
      r["network_tx_bytes"] =
          getNetworkBytes(container.get_child("networks"), "tx_bytes");
      results.push_back(r);
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error getting docker container stats " << id << ": "
              << e.what();
    }
  }

  return results;
}

/**
 * @brief Entry point for docker_networks table.
 */
QueryData genNetworks(QueryContext& context) {
  std::string query;
  std::set<std::string> ids;
  getQuery(context, "id", query, ids, false);

  QueryData results;
  pt::ptree tree;
  Status s = dockerApi("/networks" + query, tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting docker networks: " << s.what();
    return results;
  }

  for (const auto& entry : tree) {
    try {
      const pt::ptree& node = entry.second;
      Row r;
      r["id"] = getValue(node, ids, "Id");
      r["name"] = node.get<std::string>("Name", "");
      r["driver"] = node.get<std::string>("Driver", "");
      r["created"] =
          BIGINT(getUnixTime(node.get<std::string>("Created", ""), true));
      r["enable_ipv6"] =
          (node.get<bool>("EnableIPv6", false) ? INTEGER(1) : INTEGER(0));
      for (const auto& config : node.get_child("IPAM.Config")) {
        const pt::ptree& details = config.second;
        r["subnet"] = details.get<std::string>("Subnet", "");
        r["gateway"] = details.get<std::string>("Gateway", "");
        break;
      }
      results.push_back(r);
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error getting docker network details: " << e.what();
    }
  }

  return results;
}

/**
 * @brief Entry point for docker_network_labels table.
 */
QueryData genNetworkLabels(QueryContext& context) {
  return getLabels(context,
                   "network", // Docker object type
                   "id", // Look for "id" column in context
                   "Id", // Network primary key is "Id"
                   "/networks", // All networks URL
                   "", // Network array is at top level
                   true, // Supports "filters" in query string
                   false); // Does not supports "all" in query string
}

/**
 * @brief Entry point for docker_volumes table.
 */
QueryData genVolumes(QueryContext& context) {
  std::string query;
  std::set<std::string> names;
  getQuery(context, "name", query, names, false);

  QueryData results;
  pt::ptree tree;
  Status s = dockerApi("/volumes" + query, tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting docker volumes: " << s.what();
    return results;
  }

  for (const auto& entry : tree.get_child("Volumes")) {
    try {
      const pt::ptree& node = entry.second;
      Row r;
      r["name"] = getValue(node, names, "Name");
      r["driver"] = node.get<std::string>("Driver", "");
      r["mount_point"] = node.get<std::string>("Mountpoint", "");
      r["type"] = node.get<std::string>("Options.type", "");
      results.push_back(r);
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error getting docker volume details: " << e.what();
    }
  }

  return results;
}

/**
 * @brief Entry point for docker_volume_labels table.
 */
QueryData genVolumeLabels(QueryContext& context) {
  return getLabels(context,
                   "volume", // Docker object type
                   "name", // Look for "name" column in context
                   "Name", // Volume primary key is "Name"
                   "/volumes", // All volumes URL
                   "Volumes", // Volume array is under "Volumes" child node
                   true, // Supports "filters" in query string
                   false); // Does not supports "all" in query string
}

/**
 * @brief Entry point for docker_images table.
 */
QueryData genImages(QueryContext& context) {
  QueryData results;
  pt::ptree tree;
  Status s = dockerApi("/images/json", tree);
  if (!s.ok()) {
    VLOG(1) << "Error getting docker images: " << s.what();
    return results;
  }

  for (const auto& entry : tree) {
    try {
      const pt::ptree& node = entry.second;
      Row r;
      r["id"] = node.get<std::string>("Id", "");
      if (boost::starts_with(r["id"], "sha256:")) {
        r["id"].erase(0, 7);
      }
      r["created"] = BIGINT(node.get<uint64_t>("Created", 0));
      r["size_bytes"] = BIGINT(node.get<uint64_t>("Size", 0));
      std::string tags;
      for (const auto& tag : node.get_child("RepoTags")) {
        if (!tags.empty()) {
          tags.append(",");
        }
        tags.append(tag.second.data());
      }
      r["tags"] = tags;
      results.push_back(r);
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error getting docker image details: " << e.what();
    }
  }

  return results;
}

/**
 * @brief Entry point for docker_image_labels table.
 */
QueryData genImageLabels(QueryContext& context) {
  return getLabels(context,
                   "image", // Docker object type
                   "id", // Look for "id" column in context
                   "Id", // Image primary key is "Id"
                   "/images/json", // All images URL
                   "", // Image array is at top level
                   false, // Does not support "filters" query string
                   false); // Does not support "all" query string
}
} // namespace tables
} // namespace osquery
