/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <osquery/config/config.h>
#include <osquery/dispatcher.h>

namespace osquery {

class TLSConfigPlugin;

class TLSConfigPlugin : public ConfigPlugin,
                        public std::enable_shared_from_this<TLSConfigPlugin> {
 public:
  Status setUp() override;
  Status genConfig(std::map<std::string, std::string>& config) override;

 protected:
  /// Calculate the URL once and cache the result.
  std::string uri_;

 private:
  friend class TLSConfigTests;
};
} // namespace osquery
