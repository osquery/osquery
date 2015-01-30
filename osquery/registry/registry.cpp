/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <boost/property_tree/json_parser.hpp>

#include <osquery/registry.h>

namespace osquery {

void Plugin::getResponse(const std::string& key,
                         const PluginResponse& response,
                         boost::property_tree::ptree& tree) {
  for (const auto& item : response) {
    boost::property_tree::ptree child;
    for (const auto& item_detail : item) {
      child.put(item_detail.first, item_detail.second);
    }
    tree.add_child(key, child);
  }
}

void Plugin::setResponse(const std::string& key,
                         const boost::property_tree::ptree& tree,
                         PluginResponse& response) {
  std::ostringstream output;
  boost::property_tree::write_json(output, tree, false);
  response.push_back({{key, output.str()}});
}
}
