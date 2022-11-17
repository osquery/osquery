/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/optional.hpp>

#include <osquery/events/windows/etw/etw_data_event.h>

namespace osquery {

class Status;

/**
 * @brief EtwProviderConfig abstracts the configurable aspects of an ETW
 * provider. It also provides a mechanism to set and retrieve provider-specific
 * callbacks for pre-processing and post-processing logic on events originating
 * from this provider.
 */
class EtwProviderConfig {
 public:
  /**
   * @brief Supported kernel providers
   */
  enum class EtwKernelProviderType {
    Invalid,
    File,
    ImageLoad,
    Network,
    Process,
    Registry,
    ObjectManager
  };

  using EtwProviderName = std::string;
  using EtwBitmask = boost::optional<std::uint64_t>;
  using EtwInteger = boost::optional<std::uint64_t>;
  using EtwLevel = boost::optional<std::uint8_t>;
  using EtwKernelProviderStatus = boost::optional<bool>;
  using EventProviderPreProcessor = krabs::c_provider_callback;
  using EventProviderPostProcessor =
      std::function<void(const EtwEventDataRef&)>;

 public:
  /**
   * @brief It returns the set pre-processor callback function
   */
  const EventProviderPreProcessor& getPreProcessor() const;

  /**
   * @brief It returns the set post-processor callback function
   */
  const EventProviderPostProcessor& getPostProcessor() const;

  /**
   * @brief It sets the pre-processor callback function
   *
   * @param value is a function pointer to the callback function to be used to
   * pre-process the events arriving from the ETW provider. The callback should
   * have the signature defined by EventProviderPreProcessor. Note that the
   * signature corresponds to a function pointer.
   */
  void setPreProcessor(const EventProviderPreProcessor& value);

  /**
   * @brief It sets the post-processor callback function
   *
   * @param value is a function pointer to the callback function to be used to
   * post-process the events arriving from the ETW provider. The callback should
   * have the signature defined by EventProviderPostProcessor. Note that the
   * signature corresponds to a std::function.
   */
  void setPostProcessor(const EventProviderPostProcessor& value);

  // Helpers to determine if optional flags were set
  bool isAnyBitmaskSet() const;
  bool isAllBitmaskSet() const;
  bool isLevelSet() const;
  bool isTraceFlagsSet() const;
  bool isTagSet() const;
  bool isUserProvider() const;

  // Helpers to retrieve the value of optional flags
  EtwProviderName getName() const;
  EtwKernelProviderType getKernelProviderType() const;
  EtwBitmask getAnyBitmask() const;
  EtwBitmask getAllBitmask() const;
  EtwLevel getLevel() const;
  EtwInteger getTraceFlags() const;
  EtwInteger getTag() const;

  // Helpers to set the value of optional flags
  void setName(const EtwProviderName& value);
  void setKernelProviderType(const EtwKernelProviderType& value);
  void setAnyBitmask(const EtwBitmask& value);
  void setAllBitmask(const EtwBitmask& value);
  void setLevel(const EtwLevel& value);
  void setTraceFlags(const EtwInteger& value);
  void setTag(const EtwInteger& value);

  /**
   * @brief It checks if EtwProviderConfig contains valid and expected data
   */
  Status isValid() const;

 private:
  EtwProviderName providerName_;
  EtwKernelProviderType kernelProviderType_{EtwKernelProviderType::Invalid};
  EventProviderPreProcessor providerPreProcess_{nullptr};
  EventProviderPostProcessor providerPostProcess_{nullptr};
  EtwBitmask keywordsAny_{boost::none};
  EtwBitmask keywordsAll_{boost::none};
  EtwLevel level_{boost::none};
  EtwInteger traceFlags_{boost::none};
  EtwInteger tag_{boost::none};
  bool isUserProvider_{true};
};

} // namespace osquery