/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <mutex>

#include <osquery/config/config.h>
#include <osquery/dispatcher/dispatcher.h>

namespace osquery {

class TLSConfigPlugin;

class TLSConfigPlugin : public ConfigPlugin,
                        public std::enable_shared_from_this<TLSConfigPlugin> {
 public:
  Status setUp() override;
  Status genConfig(std::map<std::string, std::string>& config) override;
  Status configApplied() override;

 protected:
  /// Calculate the URL once and cache the result.
  std::string uri_;

 private:
  /// Validator of the last config received from the server, echoed back in
  /// subsequent request bodies. Opaque and server-assigned; never computed
  /// by the client.
  std::string etag_;

  /// Whether the config identified by etag_ was successfully applied.
  bool applied_{false};

  /// Guards etag_/applied_ during the startup overlap window
  /// (Config::load vs. ConfigRefreshRunner).
  std::mutex mutex_;

  friend class TLSConfigTests;
};
} // namespace osquery
