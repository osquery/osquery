/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <memory>
#include <utility>
#include <string>

#include <boost/property_tree/ptree.hpp>

#include <osquery/logger.h>
#include <osquery/status.h>

namespace osquery {

class Serializer;

/**
 * @brief Compress data using GZip.
 *
 * Requests API callers may request data be compressed before sending.
 * The compression step occurs after serialization, immediately before the
 * transport call.
 *
 * @param data The input/output mutable container.
 */
std::string compressString(const std::string& data);

/**
 * @brief Abstract base class for remote transport implementations
 *
 * To define a new transport mechanism (HTTP, WebSockets, etc) for use with
 * remote connections, subclass osquery::Transport and implement the pure
 * virtual methods (as well as any base methods you may want to implement
 * custom behavior for).
 */
class Transport {
 public:
  /**
   * @brief Set the destination URI
   *
   * @param A string representing the destination
   *
   * @return success or failure of the operation
  */
  virtual void setDestination(const std::string& destination) {
    destination_ = destination;
  }

  /**
   * @brief Set the serializer
   *
   * @param A serializer object
   */
  virtual void setSerializer(const std::shared_ptr<Serializer>& serializer) {
    serializer_ = serializer;
  }

  /**
   * @brief Send a simple request to the destination with no parameters
   *
   * @return success or failure of the operation
   */
  virtual Status sendRequest() = 0;

  /**
   * @brief Send a simple request to the destination with parameters
   *
   * @param params A string representing the serialized parameters
   * @param compress True of the request was requested to be compressed
   *
   * @return success or failure of the operation
   */
  virtual Status sendRequest(const std::string& params,
                             bool compress = false) = 0;

  /**
   * @brief Get the status of the response
   *
   * @return success or failure of the operation
   */
  Status getResponseStatus() const { return response_status_; }

  /**
   * @brief Get the parameters of the response
   *
   * @return The parameters
   */
  const boost::property_tree::ptree& getResponseParams() const {
    return response_params_;
  }

  template <typename T>
  void setOption(const std::string& name, const T& value) {
    options_.put(name, value);
  }

  /**
   * @brief Virtual destructor
   */
  virtual ~Transport() {}

 protected:
  /// storage for the transport destination
  std::string destination_;

  /// storage for the serializer reference
  std::shared_ptr<Serializer> serializer_{nullptr};

  /// storage for response status
  Status response_status_;

  /// storage for response parameters
  boost::property_tree::ptree response_params_;

  /// options from request call (use defined by specific transport)
  boost::property_tree::ptree options_;
};

/**
 * @brief Abstract base class for serialization implementations
 *
 * To define a new serialization mechanism (JSON, XML, etc) for use with
 * remote connections, subclass osquery::Serializer and implement the pure
 * virtual methods (as well as any base methods you may want to implement
 * custom behavior for).
 */
class Serializer {
 public:
  /**
   * @brief Returns the HTTP content type, for HTTP/TLS transport
   *
   * If a serializer is going to be used for HTTP/TLS, it probably needs to
   * set its own content type. Return a string with the appropriate content
   * type for serializer.
   *
   * @return The content type
   */
  virtual std::string getContentType() const = 0;

  /**
   * @brief Serialize a property tree into a string
   *
   * @param params A property tree of parameters
   * @param serialized the output serialized params
   * @return success or failure of the operation
   */
  virtual Status serialize(const boost::property_tree::ptree& params,
                           std::string& serialized) = 0;

  /**
   * @brief Deserialize a property tree into a property tree
   *
   * @param params A string of serialized parameters
   * @param serialized the output deserialized parameters
   * @return success or failure of the operation
   */
  virtual Status deserialize(const std::string& serialized,
                             boost::property_tree::ptree& params) = 0;

  /**
   * @brief Virtual destructor
   */
  virtual ~Serializer() {}
};

/**
 * @brief Request class for making flexible remote network requests
 */
template <class TTransport, class TSerializer>
class Request {
 public:
  /**
   * @brief This is the constructor that you should use to instantiate Request
   *
   * @param destination A string of the remote URI destination
   */
  explicit Request(const std::string& destination)
      : destination_(destination),
        serializer_(std::make_shared<TSerializer>()),
        transport_(std::make_shared<TTransport>()) {
    transport_->setDestination(destination_);
    transport_->setSerializer(serializer_);
  }

 private:
  /**
   * @brief Create a request with a customized Transport (testing only).
   *
   * @param destination A string of the remote URI destination
   * @param t A transport shared pointer.
   */
  Request(const std::string& destination, const std::shared_ptr<TTransport>& t)
      : destination_(destination),
        serializer_(std::make_shared<TSerializer>()),
        transport_(t) {
    transport_->setDestination(destination_);
    transport_->setSerializer(serializer_);
  }

 public:
  /**
   * @brief Class destructor
   */
  virtual ~Request() {}

  /**
   * @brief Send a simple request to the destination with no parameters
   *
   * @return success or failure of the operation
   */
  Status call() { return transport_->sendRequest(); }

  /**
   * @brief Send a simple request to the destination with parameters
   *
   * @param params A property tree representing the parameters
   *
   * @return success or failure of the operation
   */
  Status call(const boost::property_tree::ptree& params) {
    std::string serialized;
    auto s = serializer_->serialize(params, serialized);
    if (!s.ok()) {
      return s;
    }

    return transport_->sendRequest(serialized, options_.get("compress", false));
  }

  /**
   * @brief Get the request response
   *
   * @return A pair of a Status and a property tree of response params
   */
  Status getResponse(boost::property_tree::ptree& params) {
    params = transport_->getResponseParams();
    return transport_->getResponseStatus();
  }

  template <typename T>
  void setOption(const std::string& name, const T& value) {
    options_.put(name, value);
    transport_->setOption(name, value);
  }

 private:
  /// storage for the resource destination
  std::string destination_;

  /// storage for the serializer to be used
  std::shared_ptr<TSerializer> serializer_{nullptr};

  /// storage for the transport to be used
  std::shared_ptr<TTransport> transport_{nullptr};

  /// options from request call (duplicated in transport)
  boost::property_tree::ptree options_;

 private:
  FRIEND_TEST(TLSTransportsTests, test_call);
  FRIEND_TEST(TLSTransportsTests, test_call_with_params);
  FRIEND_TEST(TLSTransportsTests, test_call_verify_peer);
  FRIEND_TEST(TLSTransportsTests, test_call_server_cert_pinning);
  FRIEND_TEST(TLSTransportsTests, test_call_client_auth);

  friend class TestDistributedPlugin;
};
}
