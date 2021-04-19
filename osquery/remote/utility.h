/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <chrono>

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include <osquery/remote/transports/tls.h>
// clang-format on

#include <osquery/remote/enroll/enroll.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/core/shutdown.h>

#include <osquery/process/process.h>
#include <osquery/remote/requests.h>

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
 * don't.
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
   * @param params is a JSON object containing the params to send to the server.
   * This isn't const because it will be modified to include node_key.
   * @param output is the JSON which will be populated with the deserialized
   * results
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri, JSON& params, JSON& output) {
    auto& params_doc = params.doc();
    auto& output_doc = output.doc();

    auto node_key = getNodeKey("tls");

    // If using a GET request, append the node_key to the URI variables.
    std::string uri_suffix;
    if (FLAGS_tls_node_api) {
      uri_suffix = "&node_key=" + node_key;
    } else {
      params.add("node_key", node_key);
    }

    // Again check for GET to call with/without parameters.
    Request<TLSTransport, TSerializer> request(uri + uri_suffix);
    request.setOption("hostname", FLAGS_tls_hostname);

    bool compress = false;
    auto it = params_doc.FindMember("_compress");
    if (it != params_doc.MemberEnd()) {
      compress = true;
      request.setOption("compress", compress);
      params_doc.RemoveMember("_compress");
    }

    // The caller-supplied parameters may force a POST request.
    bool force_post = false;
    it = params_doc.FindMember("_verb");
    if (it != params_doc.MemberEnd()) {
      assert(it->value.IsString());

      force_post = std::string(it->value.GetString()) == "POST";
      params_doc.RemoveMember("_verb");
    }

    bool use_post = true;
    it = params_doc.FindMember("_get");
    if (it != params_doc.MemberEnd()) {
      use_post = false;
      params_doc.RemoveMember("_get");
    }
    bool should_post = (use_post || force_post);
    auto status = (should_post) ? request.call(params) : request.call();

    // Restore caller-supplied parameters.
    if (force_post) {
      params.add("_verb", "POST");
    }

    if (compress) {
      params.add("_compress", true);
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
    it = output_doc.FindMember("node_invalid");
    if (it != output_doc.MemberEnd()) {
      assert(it->value.IsBool());

      if (it->value.GetBool()) {
        if (!FLAGS_disable_reenrollment) {
          clearNodeKey();
        }

        std::string message = "Request failed: Invalid node key";

        it = output_doc.FindMember("error");
        if (it != output_doc.MemberEnd()) {
          message +=
              ": " + std::string(it->value.IsString() ? it->value.GetString()
                                                      : "<unknown>");
        }

        return Status(1, message);
      }
    }

    it = output_doc.FindMember("error");
    if (it != output_doc.MemberEnd()) {
      std::string message =
          "Request failed: " + std::string(it->value.IsString()
                                               ? it->value.GetString()
                                               : "<unknown>");

      return Status(1, message);
    }

    return Status::success();
  }

  /**
   * @brief Send a TLS request
   *
   * @param uri is the URI to send the request to
   * @param output is a JSON object containing the output from the server
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri, JSON& output) {
    JSON params;
    params.add("_get", true);
    return TLSRequestHelper::go<TSerializer>(uri, params, output);
  }

  /**
   * @brief Send a TLS request
   *
   * @param uri is the URI to send the request to
   * @param params is a JSON object containing the params to send to the server.
   * This isn't const because it will be modified to include node_key.
   * @param output is the string which will be populated with the deserialized
   * results
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri, JSON& params, std::string& output) {
    JSON recv;
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
    JSON params;
    params.add("_get", true);
    return TLSRequestHelper::go<TSerializer>(uri, params, output);
  }

  /**
   * @brief Send a TLS request
   *
   * @param uri is the URI to send the request to
   * @param params is a JSON object containing the params to send to the server.
   * This isn't const because it will be modified to include node_key.
   * @param output is the string which will be populated with the deserialized
   * results
   * @param attempts is the number of attempts to make if the request fails
   *
   * @return a Status object indicating the success or failure of the operation
   */
  template <class TSerializer>
  static Status go(const std::string& uri,
                   JSON& params,
                   std::string& output,
                   const uint64_t attempts) {
    Status s;
    JSON override_params;
    const auto& params_doc = params.doc();
    const auto& override_params_doc = override_params.doc();

    for (auto& m : params_doc.GetObject()) {
      std::string name = m.name.GetString();
      if (name.find('_') == 0) {
        override_params.add(name, m.value);
      }
    }

    bool should_shutdown = false;
    for (size_t i = 1; i <= attempts && !should_shutdown; i++) {
      s = TLSRequestHelper::go<TSerializer>(uri, params, output);
      if (s.ok()) {
        return s;
      }
      if (i == attempts) {
        break;
      }
      for (auto& m : override_params_doc.GetObject()) {
        params.add(m.name.GetString(), m.value);
      }

      should_shutdown =
          waitTimeoutOrShutdown(std::chrono::milliseconds(i * i * 1000));
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
    JSON params;
    params.add("_get", true);
    return TLSRequestHelper::go<TSerializer>(uri, params, output, attempts);
  }
};
} // namespace osquery
