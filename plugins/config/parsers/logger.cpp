/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/registry/registry_factory.h>
#include <plugins/config/parsers/logger.h>

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
