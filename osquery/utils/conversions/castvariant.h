/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <boost/lexical_cast.hpp>
#include <string>

namespace osquery {

/* We do this so that we get '0.0' from double 0.0 instead of '0'
 */
class CastVisitor : public boost::static_visitor<std::string> {
 public:
  std::string operator()(const long long& i) const {
    return std::to_string(i);
  }

  std::string operator()(const double& d) const {
    std::string s{boost::lexical_cast<std::string>(d)};
    if (s.find('.') == std::string::npos) {
      s += ".0";
    }
    return s;
  }

  std::string operator()(const std::string& str) const {
    return str;
  }
};

inline std::string castVariant(
    const boost::variant<long long, double, std::string>& var) {
  static const CastVisitor visitor;
  return boost::apply_visitor(visitor, var);
}
} // namespace osquery
