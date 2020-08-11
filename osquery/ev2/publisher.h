/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/ev2/subscription.h>
#include <osquery/utils/expected/expected.h>

#include <memory>
#include <string>

namespace osquery {
namespace ev2 {

/**
 * @brief Event publisher responsible for processing events of a certain type
 * and publish them to registered ev2::Subscription instances.
 *
 * @details A ev2::Publisher is the responsible for processing events coming
 * from producers and forwarding them to the registered ev2::Subscription
 * instances. This class is meant to be specialized by consumers according to
 * their needs.
 */
class Publisher {
 public:
  /**
   * @brief Errors return by this class' methods.
   */
  enum class Error {
    InvalidSubscription,
  };

  /**
   * @brief ev2::Publisher constructor.
   *
   * @params name Publisher name.
   */
  explicit Publisher(std::string name);
  virtual ~Publisher() = default;

  /**
   * @brief Retrieve the publisher name.
   *
   * @returns A const reference to the publisher name with the lifetime of the
   * ev2::Publisher object.
   */
  const std::string& name() const;

  /**
   * @brief Subscribe to this publisher.
   *
   * @details If successful the publisher will start forwarding events to the
   * provided ev2::Subscription.
   */
  virtual ExpectedSuccess<Error> subscribe(
      std::shared_ptr<Subscription> subscription) = 0;

 private:
  const std::string name_;
};

} // namespace ev2
} // namespace osquery
