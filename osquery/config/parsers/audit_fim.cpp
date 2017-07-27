/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include <iostream>

#include <boost/property_tree/json_parser.hpp>
namespace pt = boost::property_tree;

namespace osquery {

class AuditFimConfigParserPlugin final : public ConfigParserPlugin {
 public:
  AuditFimConfigParserPlugin() {
    data_.put_child("file_paths", pt::ptree());
    data_.put_child("exclude", pt::ptree());
    data_.put_child("show_accesses", pt::ptree());
  }

  virtual ~AuditFimConfigParserPlugin() = default;

  std::vector<std::string> keys() const override {
    return {"auditd_fim"};
  }

  Status setUp() override {
    return Status(0);
  };

  Status update(const std::string& source, const ParserConfig& config) override;
};

Status AuditFimConfigParserPlugin::update(const std::string& source,
                                          const ParserConfig& config) {
  auto root_key = config.at("auditd_fim");

  if (root_key.find("file_paths") != root_key.not_found()) {
    data_.put_child("file_paths", root_key.get_child("file_paths"));
  }

  if (root_key.find("exclude") != root_key.not_found()) {
    data_.put_child("exclude", root_key.get_child("exclude"));
  }

  if (root_key.find("show_accesses") != root_key.not_found()) {
    data_.put_child("show_accesses", root_key.get_child("show_accesses"));
  }

  return Status(0, "OK");
}

REGISTER_INTERNAL(AuditFimConfigParserPlugin, "config_parser", "audit_fim");
}
