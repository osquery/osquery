/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/variant.hpp>
#include <iomanip>
#include <sstream>
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
    std::ostringstream ss;
    // SQLite supports 15 significant digits.
    // The value of std::numeric_limits<T>::digits10 is the number of base-10
    // digits that can be represented by the type T without change, that is, any
    // number with this many significant decimal digits can be converted to a
    // value of type T and back to decimal form, without change due to rounding
    // or overflow. (from cppreference.com)
    ss << std::setprecision(std::numeric_limits<double>::digits10) << d;
    std::string s = ss.str();
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
