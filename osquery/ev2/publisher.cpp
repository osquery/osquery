/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/ev2/publisher.h>

namespace osquery {
namespace ev2 {

Publisher::Publisher(std::string name) : name_(name) {}

const std::string& Publisher::name() const {
  return name_;
}

} // namespace ev2
} // namespace osquery
