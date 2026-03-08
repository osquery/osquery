/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/networking/curl.h>

namespace osquery {
namespace tables {

class CurlTests : public testing::Test {};

TEST_F(CurlTests, test_sanitize_http_header_value_empty) {
  EXPECT_EQ(sanitizeHttpHeaderValue(""), "");
}

TEST_F(CurlTests, test_sanitize_http_header_value_normal) {
  // Normal strings should pass through unchanged
  EXPECT_EQ(sanitizeHttpHeaderValue("osquery"), "osquery");
  EXPECT_EQ(sanitizeHttpHeaderValue("Mozilla/5.0"), "Mozilla/5.0");
  EXPECT_EQ(sanitizeHttpHeaderValue("Custom User Agent 1.0"),
            "Custom User Agent 1.0");
}

TEST_F(CurlTests, test_sanitize_http_header_value_removes_lf) {
  // Line feed characters should be removed
  EXPECT_EQ(sanitizeHttpHeaderValue("test\nvalue"), "testvalue");
  EXPECT_EQ(sanitizeHttpHeaderValue("\nstart"), "start");
  EXPECT_EQ(sanitizeHttpHeaderValue("end\n"), "end");
  EXPECT_EQ(sanitizeHttpHeaderValue("\n"), "");
}

TEST_F(CurlTests, test_sanitize_http_header_value_removes_cr) {
  // Carriage return characters should be removed
  EXPECT_EQ(sanitizeHttpHeaderValue("test\rvalue"), "testvalue");
  EXPECT_EQ(sanitizeHttpHeaderValue("\rstart"), "start");
  EXPECT_EQ(sanitizeHttpHeaderValue("end\r"), "end");
  EXPECT_EQ(sanitizeHttpHeaderValue("\r"), "");
}

TEST_F(CurlTests, test_sanitize_http_header_value_removes_crlf) {
  // CRLF sequences should be completely removed
  EXPECT_EQ(sanitizeHttpHeaderValue("test\r\nvalue"), "testvalue");
  EXPECT_EQ(sanitizeHttpHeaderValue("\r\nstart"), "start");
  EXPECT_EQ(sanitizeHttpHeaderValue("end\r\n"), "end");
  EXPECT_EQ(sanitizeHttpHeaderValue("\r\n"), "");
}

TEST_F(CurlTests, test_sanitize_http_header_value_header_injection_attack) {
  // This is the actual attack vector from issue #8404
  // An attacker tries to inject headers via the user_agent field
  std::string malicious_ua =
      "Satoki\r\nmaliciousheader: omg\r\nmaliciousheader2: omg";
  std::string sanitized = sanitizeHttpHeaderValue(malicious_ua);

  // The sanitized string should have no newlines
  EXPECT_EQ(sanitized.find('\r'), std::string::npos);
  EXPECT_EQ(sanitized.find('\n'), std::string::npos);

  // The result should be the concatenation without the CRLF chars
  EXPECT_EQ(sanitized, "Satokimaliciousheader: omgmaliciousheader2: omg");
}

TEST_F(CurlTests, test_sanitize_http_header_value_cloud_metadata_attack) {
  // Attack to access cloud metadata service
  std::string malicious_ua = "osquery\r\nMetadata-Flavor: Google";
  std::string sanitized = sanitizeHttpHeaderValue(malicious_ua);

  EXPECT_EQ(sanitized.find('\r'), std::string::npos);
  EXPECT_EQ(sanitized.find('\n'), std::string::npos);
  EXPECT_EQ(sanitized, "osqueryMetadata-Flavor: Google");
}

TEST_F(CurlTests, test_sanitize_http_header_value_multiple_injections) {
  // Multiple injection attempts
  std::string malicious_ua = "ua\r\nHeader1: val1\r\nHeader2: val2\r\n";
  std::string sanitized = sanitizeHttpHeaderValue(malicious_ua);

  EXPECT_EQ(sanitized.find('\r'), std::string::npos);
  EXPECT_EQ(sanitized.find('\n'), std::string::npos);
}

TEST_F(CurlTests, test_sanitize_http_header_value_preserves_special_chars) {
  // Other special characters should be preserved
  EXPECT_EQ(sanitizeHttpHeaderValue("test\ttab"), "test\ttab");
  EXPECT_EQ(sanitizeHttpHeaderValue("test space"), "test space");
  EXPECT_EQ(sanitizeHttpHeaderValue("test:colon"), "test:colon");
  EXPECT_EQ(sanitizeHttpHeaderValue("test;semicolon"), "test;semicolon");
}

} // namespace tables
} // namespace osquery
