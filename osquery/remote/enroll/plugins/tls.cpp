/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/enroll.h>
#include <osquery/filesystem.h>
#include <osquery/system.h>

#include <osquery/sql.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"

// Ordering is messed up because of tls.h
#include "osquery/core/conversions.h"
#include "osquery/core/process.h"

#include "tls.h"

namespace pt = boost::property_tree;

namespace osquery {

DECLARE_string(enroll_secret_path);
DECLARE_bool(disable_enrollment);

/// Enrollment TLS endpoint (path) using TLS hostname.
CLI_FLAG(string,
         enroll_tls_endpoint,
         "",
         "TLS/HTTPS endpoint for client enrollment");

/// Additional metadata to send with enrollment request
CLI_FLAG(string,
         enroll_tls_metadata,
         "",
         "Semicolon separated list of query specs whose results will be sent\n"
         "as part of enroll request. Each query spec is in the form "
         "\"Name:SQL Query\".\n"
         "Metadata will be returned in arrays named \"Name\"");

/// Undocumented feature for TLS access token passing.
HIDDEN_FLAG(bool,
            tls_secret_always,
            false,
            "Include TLS enroll secret in every request");

/// Undocumented feature to override TLS enrollment key name.
HIDDEN_FLAG(string,
            tls_enroll_override,
            "enroll_secret",
            "Override the TLS enroll secret key name");

DECLARE_uint64(config_tls_max_attempts);

REGISTER(TLSEnrollPlugin, "enroll", "tls");

std::string TLSEnrollPlugin::enroll() {
  // If no node secret has been negotiated, try a TLS request.
  auto uri = "https://" + FLAGS_tls_hostname + FLAGS_enroll_tls_endpoint;
  if (FLAGS_tls_secret_always) {
    uri += ((uri.find("?") != std::string::npos) ? "&" : "?") +
           FLAGS_tls_enroll_override + "=" + getEnrollSecret();
  }

  std::string node_key;
  VLOG(1) << "TLSEnrollPlugin requesting a node enroll key from: " << uri;
  for (size_t i = 1; i <= FLAGS_config_tls_max_attempts; i++) {
    auto status = requestKey(uri, node_key);
    if (status.ok() || i == FLAGS_config_tls_max_attempts) {
      break;
    }

    LOG(WARNING) << "Failed enrollment request to " << uri << " ("
                 << status.what() << ") retrying...";
    sleepFor(i * i * 1000);
  }

  return node_key;
}

void getEnrollMetadata(pt::ptree& params) {
  // If no enroll metadata was specified on command line, return
  if (FLAGS_enroll_tls_metadata.length() == 0) {
    return;
  }

  // enroll metadata query specs are specified as a single string of the format
  // "<name>:<query>;<name>:<query>"
  auto metadata_query_specs = split(FLAGS_enroll_tls_metadata, ";");

  for (auto& metadata_query_spec : metadata_query_specs) {
    if (metadata_query_spec.length() == 0) {
      // looks like an extra semi-colon, or a semi-colon at the end of the last
      // query-spec. Ignore
      continue;
    }
    // split the query-spec into its name and query components
    auto metadata_name_query = split(metadata_query_spec, ":");
    if (metadata_name_query.size() == 2 &&
        metadata_name_query[0].length() > 0 && // Query Name
        metadata_name_query[1].length() > 0) { // The actual SQL query

      auto sql_table = SQL(metadata_name_query[1]);

      if (sql_table.ok() && sql_table.rows().size() > 0) {
        pt::ptree query_tree;
        auto status = serializeQueryData(sql_table.rows(), query_tree);
        params.put_child(metadata_name_query[0], query_tree);
      } else {
        LOG(WARNING) << "Enroll metadata Query failed or returned 0 rows:\n"
                     << "Query: [" << metadata_name_query[1] << "]\n"
                     << "Status: " << sql_table.getMessageString();
      }

    } else {
      LOG(WARNING) << "Invalid enroll metadata query spec: ["
                   << metadata_query_spec << "]";
    }
  }
}

Status TLSEnrollPlugin::requestKey(const std::string& uri,
                                   std::string& node_key) {
  // Read the optional enrollment secret data (sent with an enrollment request).
  pt::ptree params;
  params.put<std::string>(FLAGS_tls_enroll_override, getEnrollSecret());
  params.put<std::string>("host_identifier", getHostIdentifier());

  // Add any additional query results specified on the command line via
  // enroll_tls_metadata option
  getEnrollMetadata(params);

  auto request = Request<TLSTransport, JSONSerializer>(uri);
  request.setOption("hostname", FLAGS_tls_hostname);
  auto status = request.call(params);
  if (!status.ok()) {
    return status;
  }

  // The call succeeded, store the node secret key (the enrollment response).
  boost::property_tree::ptree recv;
  status = request.getResponse(recv);
  if (!status.ok()) {
    return status;
  }

  // Support multiple response keys as a node key (identifier).
  if (recv.count("node_key") > 0) {
    node_key = recv.get("node_key", "");
  } else if (recv.count("id") > 0) {
    node_key = recv.get("id", "");
  }

  if (node_key.size() == 0) {
    return Status(1, "No node key returned from TLS enroll plugin");
  }
  return Status(0, "OK");
}
}
