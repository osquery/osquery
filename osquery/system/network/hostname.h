/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/utils/schemer/schemer.h>

#include <string>

namespace osquery {

class HostIdentity final {
 public:
  explicit HostIdentity() = default;

  static HostIdentity localhost();

  template <typename Archive, typename ValueType>
  static void discloseSchema(Archive& a, ValueType& inst) {
    schemer::record(a, "fqdn", inst.fqdn);
    schemer::record(a, "uuid", inst.uuid);
  }

 public:
  std::string fqdn;
  std::string uuid;
};

} // namespace osquery
