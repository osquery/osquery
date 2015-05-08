/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
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
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
  */
  virtual void setDestination(std::string destination) {
    destination_ = destination;
  }

  /**
   * @brief Set the serializer
   *
   * @param A serializer object
   */
  virtual void setSerializer(std::shared_ptr<Serializer> serializer) {
    serializer_ = serializer;
  }

  /**
   * @brief Send a simple request to the destination with no parameters
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  virtual Status sendRequest() = 0;

  /**
   * @brief Send a simple request to the destination with parameters
   *
   * @param params A string representing the serialized parameters
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  virtual Status sendRequest(const std::string& params) = 0;

  /**
   * @brief Get the status of the response
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
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

  /**
   * @brief Virtual destructor
   */
  virtual ~Transport() {}

 protected:
  /// storage for the transport destination
  std::string destination_;

  /// storage for the serializer reference
  std::shared_ptr<Serializer> serializer_;

  /// storage for response status
  Status response_status_;

  /// storage for response parameters
  boost::property_tree::ptree response_params_;
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
   * @brief Set the transport
   *
   * @param A transport object
   */
  virtual void setTransport(std::shared_ptr<Transport> transport) {
    transport_ = transport;
  }

  /**
   * @brief Returns the HTTP content type, for HTTP/TLS transport
   *
   * If a serializer is going to be used for HTTP/TLS, it probably needs to
   * set it's own content type. Return a string with the appropriate content
   * type for serializer.
   *
   * @return The content type
   */
  virtual std::string getContentType() const = 0;

  /**
   * @brief Serialize a property tree into a string
   *
   * @param params A property tree of parameters
   *
   * @param serialized The string to populate the final serialized params into
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  virtual Status serialize(const boost::property_tree::ptree& params,
                           std::string& serialized) = 0;

  /**
   * @brief Deserialize a property tree into a property tree
   *
   * @param params A string of serialized parameters
   *
   * @param serialized The property tree to populate the final serialized
   * params into
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  virtual Status deserialize(const std::string& serialized,
                             boost::property_tree::ptree& params) = 0;

  /**
   * @brief Virtual destructor
   */
  virtual ~Serializer() {}

 protected:
  /// storage for the transport reference
  std::shared_ptr<Transport> transport_;
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
  Request(const std::string& destination)
      : destination_(destination),
        serializer_(new TSerializer),
        transport_(new TTransport) {
    transport_->setDestination(destination_);
    transport_->setSerializer(serializer_);
    serializer_->setTransport(transport_);
  }

  /**
   * @brief Class destructor
   */
  virtual ~Request() {}

  /**
   * @brief Send a simple request to the destination with no parameters
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  Status call() { return transport_->sendRequest(); }

  /**
   * @brief Send a simple request to the destination with parameters
   *
   * @param params A property tree representing the parameters
   *
   * @return An instance of osquery::Status indicating the success or failure
   * of the operation
   */
  Status call(const boost::property_tree::ptree& params) {
    std::string serialized;
    auto s = serializer_->serialize(params, serialized);
    if (!s.ok()) {
      return s;
    }
    return transport_->sendRequest(serialized);
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

 private:
  /// storage for the resource destination
  std::string destination_;

  /// storage for the serializer to be used
  std::shared_ptr<TSerializer> serializer_;

  /// storage for the transport to be used
  std::shared_ptr<TTransport> transport_;
};
}
