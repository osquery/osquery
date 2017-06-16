/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/enroll.h>
#include <osquery/flags.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/transports/tls.h"

#include "osquery/core/process.h"

namespace osquery {

DECLARE_string(tls_enroll_override);
DECLARE_string(tls_hostname);
DECLARE_bool(tls_node_api);
DECLARE_bool(tls_secret_always);
DECLARE_bool(disable_reenrollment);

/**
 * @brief Helper class for allowing TLS plugins to easily kick off requests
 *
 * There are many static functions in this class that have very similar
 * behavior, which allow them to be used in many context. Some methods accept
 * parameters, some don't require them. Some have built-in retry logic, some
 * don't. Some return results in a ptree, some return results in JSON, etc.
 */
class TLSRequestHelper : private boost::noncopyable {
 public:
  /**
   * @brief Using the `tls_hostname` flag and an endpoint, construct a URI
   *
   * @param endpoint is the URI endpoint to be combined with `tls_hostname`
   * @return a string representing the uri
   */
  static std::string makeURI(const std::string& endpoint) {
    auto node_key = getNodeKey("tls");
    auto uri = "https://" + FLAGS_tls_hostname;
    if (FLAGS_tls_node_api) {
      // The TLS API should treat clients as nodes.
      // In this case the node_key acts as an identifier (node) and the
      // endpoints
      // (if provided) are treated as edges from the nodes.
      uri += "/" + node_key;
    }
    uri += endpoint;

    // Some APIs may require persistent identification.
    if (FLAGS_tls_secret_always) {
      uri += ((uri.find('?') != std::string::npos) ? "&" : "?") +
             FLAGS_tls_enroll_override + "=" + getEnrollSecret();
    }
    return uri;
  }

  /**
   * @brief Send a TLS request
   *
   * @param uri is the URI to send the request to
   * @param params is a ptree of the params to send to the server. This isn't
   * const because it will be modified to include node_key.
   * @param output is the ptree which will be populated with the deserialized
   * results
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri,
                   boost::property_tree::ptree& params,
                   boost::property_tree::ptree& output) {
    auto node_key = getNodeKey("tls");

    // If using a GET request, append the node_key to the URI variables.
    std::string uri_suffix;
    if (FLAGS_tls_node_api) {
      uri_suffix = "&node_key=" + node_key;
    } else {
      params.put<std::string>("node_key", node_key);
    }

    // Again check for GET to call with/without parameters.
    auto request = Request<TLSTransport, TSerializer>(uri + uri_suffix);
    request.setOption("hostname", FLAGS_tls_hostname);

    bool compress = false;
    if (params.count("_compress")) {
      compress = true;
      request.setOption("compress", true);
      params.erase("_compress");
    }

    // The caller-supplied parameters may force a POST request.
    bool force_post = false;
    if (params.count("_verb")) {
      force_post = (params.get<std::string>("_verb") == "POST");
      params.erase("_verb");
    }

    bool use_post = true;
    if (params.count("_get")) {
      use_post = false;
      params.erase("_get");
    }
    bool should_post = (use_post || force_post);
    auto status = (should_post) ? request.call(params) : request.call();

    // Restore caller-supplied parameters.
    if (force_post) {
      params.put("_verb", "POST");
    }

    if (compress) {
      params.put("_compress", true);
    }

    if (!status.ok()) {
      return status;
    }

    // The call succeeded, store the enrolled key.
    status = request.getResponse(output);
    if (!status.ok()) {
      return status;
    }

    // Receive config or key rejection
    if (output.count("node_invalid") > 0) {
      auto invalid = output.get("node_invalid", "");
      if (invalid == "1" || invalid == "true" || invalid == "True") {
        if (!FLAGS_disable_reenrollment) {
          clearNodeKey();
        }

        std::string message = "Request failed: Invalid node key";
        if (output.count("error") > 0) {
          message += ": " + output.get("error", "<unknown>");
        }
        return Status(1, message);
      }
    }

    if (output.count("error") > 0) {
      return Status(1, "Request failed: " + output.get("error", "<unknown>"));
    }

    return Status(0, "OK");
  }

  /**
   * @brief Send a TLS request
   *
   * @param uri is the URI to send the request to
   * @param output is a ptree of the output from the server
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri,
                   boost::property_tree::ptree& output) {
    boost::property_tree::ptree params;
    params.put("_get", true);
    return TLSRequestHelper::go<TSerializer>(uri, params, output);
  }

  /**
   * @brief Send a TLS request
   *
   * @param uri is the URI to send the request to
   * @param params is a ptree of the params to send to the server. This isn't
   * const because it will be modified to include node_key.
   * @param output is the string which will be populated with the deserialized
   * results
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri,
                   boost::property_tree::ptree& params,
                   std::string& output) {
    boost::property_tree::ptree recv;
    auto s = TLSRequestHelper::go<TSerializer>(uri, params, recv);
    if (s.ok()) {
      auto serializer = TSerializer();
      return serializer.serialize(recv, output);
    }
    return s;
  }

  /**
   * @brief Send a TLS request
   *
   * @param uri is the URI to send the request to
   * @param output is the string which will be populated with the deserialized
   * results
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri, std::string& output) {
    boost::property_tree::ptree params;
    params.put("_get", true);
    return TLSRequestHelper::go<TSerializer>(uri, params, output);
  }

  /**
   * @brief Send a TLS request
   *
   * @param uri is the URI to send the request to
   * @param params is a ptree of the params to send to the server. This isn't
   * const because it will be modified to include node_key.
   * @param output is the string which will be populated with the deserialized
   * results
   * @param attempts is the number of attempts to make if the request fails
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri,
                   boost::property_tree::ptree& params,
                   std::string& output,
                   const size_t attempts) {
    Status s;
    for (size_t i = 1; i <= attempts; i++) {
      s = TLSRequestHelper::go<TSerializer>(uri, params, output);
      if (s.ok()) {
        return s;
      }
      if (i == attempts) {
        break;
      }
      sleepFor(i * i * 1000);
    }
    return s;
  }

  /**
   * @brief Send a TLS request
   *
   * @param uri is the URI to send the request to
   * @param output is the string which will be populated with the deserialized
   * results
   * @param attempts is the number of attempts to make if the request fails
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri,
                   std::string& output,
                   const size_t attempts) {
    boost::property_tree::ptree params;
    params.put("_get", true);
    return TLSRequestHelper::go<TSerializer>(uri, params, output, attempts);
  }
};
}
