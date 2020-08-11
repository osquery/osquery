/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for interface_details
// Spec file: specs/interface_details.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/conversions/tryto.h>

#include <osquery/utils/info/platform_type.h>

#include <osquery/logger/logger.h>

namespace osquery {
namespace table_tests {

class InterfaceDetailsTest : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(InterfaceDetailsTest, test_sanity) {
#ifdef OSQUERY_WINDOWS
  LOG(INFO) << "Test failing on Windows, temporarily disabled";
  return;
#endif

  QueryData const rows = execute_query("select * from interface_details");
  auto verify_non_negative_or_empty = [](std::string const& value) {
    if (value.empty()) {
      return isPlatform(PlatformType::TYPE_WINDOWS);
    }
    auto cast_result = tryTo<int64_t>(value);
    if (!cast_result) {
      return false;
    }
    return cast_result.get() >= 0;
  };
  auto verify_non_empty_string_or_empty_on_win = [](std::string const& value) {
    if (value.empty()) {
      return isPlatform(PlatformType::TYPE_WINDOWS);
    }
    return true;
  };
#ifdef OSQUERY_WINDOWS
  auto verify_int_or_empty_on_win = [](std::string const& value) {
    if (value.empty()) {
      return isPlatform(PlatformType::TYPE_WINDOWS);
    }
    auto cast_result = tryTo<int64_t>(value);
    if (!cast_result) {
      return false;
    }
    return true;
  };
  auto verify_bool_or_empty_on_win = [](std::string const& value) {
    if (value.empty()) {
      return isPlatform(PlatformType::TYPE_WINDOWS);
    }
    if (value != "1" && value != "0") {
      return false;
    }
    return true;
  };
#endif
  auto const row_map = ValidationMap{
      {"interface", NonEmptyString},
      {"mac", verify_non_empty_string_or_empty_on_win},
      {"type", NonNegativeInt},
      {"mtu", verify_non_empty_string_or_empty_on_win},
      {"metric", NonNegativeInt},
      {"flags", NonNegativeInt},
      {"ipackets", verify_non_negative_or_empty},
      {"opackets", verify_non_negative_or_empty},
      {"ibytes", verify_non_negative_or_empty},
      {"obytes", verify_non_negative_or_empty},
      {"ierrors", verify_non_negative_or_empty},
      {"oerrors", verify_non_negative_or_empty},
      {"idrops", verify_non_negative_or_empty},
      {"odrops", verify_non_negative_or_empty},
      {"collisions", NonNegativeOrErrorInt},
      {"last_change", IntType},
#ifdef OSQUERY_POSIX
      {"link_speed", NonNegativeInt},
#endif
#ifdef OSQUERY_LINUX
      {"pci_slot", NormalType},
#endif
#ifdef OSQUERY_WINDOWS
      {"friendly_name", NormalType},
      {"description", NormalType},
      {"manufacturer", NormalType},
      {"connection_id", NormalType},
      {"connection_status", verify_int_or_empty_on_win},
      {"enabled", verify_bool_or_empty_on_win},
      {"physical_adapter", verify_bool_or_empty_on_win},
      {"speed", verify_non_negative_or_empty},
      {"service", NormalType},
      {"dhcp_enabled", verify_bool_or_empty_on_win},
      {"dhcp_lease_expires", NormalType},
      {"dhcp_lease_obtained", NormalType},
      {"dhcp_server", NormalType},
      {"dns_domain", NormalType},
      {"dns_domain_suffix_search_order", NormalType},
      {"dns_host_name", NormalType},
      {"dns_server_search_order", NormalType},
#endif
  };
  validate_rows(rows, row_map);
}

} // namespace table_tests
} // namespace osquery
