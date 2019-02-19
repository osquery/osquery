/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <plugins/config/parsers/logger.h>
#include <osquery/registry_factory.h>

namespace rj = rapidjson;

namespace osquery {

const std::string LoggerConfigParserPlugin::kLoggerKey{"logger"};

Status LoggerConfigParserPlugin::update(const std::string& /* source */,
                                        const ParserConfig& config) {
  rj::Document& doc = data_.doc();

  auto it = doc.FindMember(kLoggerKey);
  if (it != doc.MemberEnd()) {
    doc.EraseMember(it);
  }

  auto cv = config.find(kLoggerKey);
  if (cv != config.end()) {
    auto obj = data_.getObject();
    data_.copyFrom(cv->second.doc(), obj);
    data_.add(kLoggerKey, obj);
  }

  return Status();
}

REGISTER_INTERNAL(LoggerConfigParserPlugin, "config_parser", "logger");

} // namespace osquery
