/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <set>
#include <string>

#include <osquery/core/flags.h>
#include <osquery/core/plugins/plugin.h>
#include <osquery/utils/json/json.h>

namespace osquery {

/// Allow users to disable enrollment features.
DECLARE_bool(disable_enrollment);

/**
 * @brief These tables populate the "host_details" content.
 *
 * Enrollment plugins should send 'default' host details to enroll request
 * endpoints. This allows the enrollment service to identify the new node.
 */
extern const std::set<std::string> kEnrollHostDetails;

/**
 * @brief Superclass for enroll plugins.
 *
 * Config and Logger plugins may use some remote API. In most cases an
 * authentication and authorization step is needed. Enroll plugins are an
 * easy wrapper-type facility that other osquery plugin types can choose to
 * implement.
 *
 * An enrollment is useful when a "backend" config or logger facility requires
 * a node or shared secret. The plugins that support this "backend" will
 * request authentication secrets through their well-known enrollment plugin.
 *
 * Enrollment plugins and authentication models are complicated. It is best
 * to use a "suite" of plugins that implement an enroll, config, and log flow.
 * Please see the osquery wiki for more details on Enrollment.
 */
class EnrollPlugin : public Plugin {
 public:
  /// The EnrollPlugin PluginRequest action router.
  Status call(const PluginRequest& request, PluginResponse& response);

 protected:
  /**
   * @brief Perform enrollment on the request of a config/logger.
   *
   * The single 'enroll' plugin request action will call EnrollPlugin::enroll
   *
   * @return An enrollment secret or key material or identifier.
   */
  virtual std::string enroll() = 0;

  /**
   * @brief Populate a JSON object with host details.
   *
   * This will use kEnrollHostDetails to select from each table and
   * construct a JSON object from the results of the first row of each.
   * The input JSON object will have a key set for each table.
   *
   * @param host_details An output JSON object containing each table.
   */
  void genHostDetails(JSON& host_details);
};

/**
 * @brief Get a node key from the osquery RocksDB cache or perform node
 * enrollment.
 *
 * Enrollment allows a new node to announce to an enrollment endpoint via an
 * enroll plugin. While the details of authentication/authorization are up to
 * the plugin implementation, the endpoint may return a "node secret".
 *
 * If a node_key is requested from an enroll plugin because no current key
 * exists in the backing store, the result will be cached.
 *
 * @param enroll_plugin Name of the enroll plugin to use if no node_key set.
 * @return A unique, often private, node secret key.
 */
std::string getNodeKey(const std::string& enroll_plugin);

/**
 * @brief Delete the existing node key from the persistent storage
 *
 * @return a Status indicating the success or failure of the operation
 */
Status clearNodeKey();

/**
 * @brief Read the enrollment secret from disk.
 *
 * We suspect multiple enrollment types may require an apriori, and enterprise
 * shared, secret. Use of this enroll or deployment secret is an optional choice
 * made by the enroll plugin type.
 *
 * @return enroll_secret The trimmed content read from FLAGS_enroll_secret_path.
 */
const std::string getEnrollSecret();
} // namespace osquery
