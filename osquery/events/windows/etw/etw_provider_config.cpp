/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/windows/etw/etw_provider_config.h>
#include <osquery/utils/status/status.h>

namespace osquery {

Status EtwProviderConfig::isValid() const {
  if (getName().empty() &&
      kernelProviderType_ == EtwKernelProviderType::Invalid) {
    return Status::failure("Invalid Provider Set");
  }

  if (eventTypes_.empty()) {
    return Status::failure("Invalid list of Events to handle");
  }

  if (getPostProcessor() == nullptr) {
    return Status::failure("Type handlers were not provided");
  }

  if (getPostProcessor() == nullptr) {
    return Status::failure("Invalid Provider PostProcessor function");
  }

  return Status::success();
}

EtwProviderConfig::EtwProviderName EtwProviderConfig::getName() const {
  return providerName_;
}

EtwProviderConfig::EtwKernelProviderType
EtwProviderConfig::getKernelProviderType() const {
  return kernelProviderType_;
}

const EtwProviderConfig::EventProviderPreProcessor&
EtwProviderConfig::getPreProcessor() const {
  return providerPreProcess_;
}

const EtwProviderConfig::EventProviderPostProcessor&
EtwProviderConfig::getPostProcessor() const {
  return providerPostProcess_;
}

const EtwEventTypes& EtwProviderConfig::getEventTypes() const {
  return eventTypes_;
}

bool EtwProviderConfig::isAnyBitmaskSet() const {
  return keywordsAny_.is_initialized();
}

bool EtwProviderConfig::isAllBitmaskSet() const {
  return keywordsAll_.is_initialized();
}

bool EtwProviderConfig::isLevelSet() const {
  return level_.is_initialized();
}

bool EtwProviderConfig::isTraceFlagsSet() const {
  return traceFlags_.is_initialized();
}

bool EtwProviderConfig::isTagSet() const {
  return tag_.is_initialized();
}

bool EtwProviderConfig::isUserProvider() const {
  return isUserProvider_;
}

EtwProviderConfig::EtwBitmask EtwProviderConfig::getAnyBitmask() const {
  return keywordsAny_;
}

EtwProviderConfig::EtwBitmask EtwProviderConfig::getAllBitmask() const {
  return keywordsAll_;
}

EtwProviderConfig::EtwLevel EtwProviderConfig::getLevel() const {
  return level_;
}

EtwProviderConfig::EtwInteger EtwProviderConfig::getTraceFlags() const {
  return traceFlags_;
}

EtwProviderConfig::EtwInteger EtwProviderConfig::getTag() const {
  return tag_;
}

void EtwProviderConfig::setName(
    const EtwProviderConfig::EtwProviderName& value) {
  if (!value.empty()) {
    providerName_ = value;
  }
}

void EtwProviderConfig::setKernelProviderType(
    const EtwKernelProviderType& value) {
  if (value > EtwKernelProviderType::Invalid &&
      value <= EtwKernelProviderType::ObjectManager) {
    kernelProviderType_ = value;
    isUserProvider_ = false;
  }
}

void EtwProviderConfig::setAnyBitmask(const EtwBitmask& value) {
  keywordsAny_ = value;
}

void EtwProviderConfig::setAllBitmask(const EtwBitmask& value) {
  keywordsAll_ = value;
}

void EtwProviderConfig::setLevel(const EtwLevel& value) {
  level_ = value;
}

void EtwProviderConfig::setTraceFlags(const EtwInteger& value) {
  traceFlags_ = value;
}

void EtwProviderConfig::setTag(const EtwInteger& value) {
  tag_ = value;
}

void EtwProviderConfig::setPreProcessor(
    const EtwProviderConfig::EventProviderPreProcessor& value) {
  if (value) {
    providerPreProcess_ = value;
  }
}

void EtwProviderConfig::setPostProcessor(
    const EtwProviderConfig::EventProviderPostProcessor& value) {
  if (value) {
    providerPostProcess_ = value;
  }
}

void EtwProviderConfig::setEventTypes(const EtwEventTypes& value) {
  if (value.empty()) {
    return;
  }

  eventTypes_.insert(eventTypes_.begin(), value.begin(), value.end());
}

void EtwProviderConfig::addEventTypeToHandle(const EtwEventType& value) {
  if (value == EtwEventType::Invalid) {
    return;
  }

  eventTypes_.push_back(value);
}

} // namespace osquery