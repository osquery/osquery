/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>

#include <osquery/tables/system/posix/openssl_utils.h>

#include <cstdlib>
#include <ctime>
#include <memory>
#include <string>

namespace osquery {
namespace tables {

namespace {

/// Sets the process time zone for one test case and puts it back after
class ScopedTimeZone final {
 public:
  explicit ScopedTimeZone(const std::string& zone) {
    auto current = getenv("TZ");
    if (current != nullptr) {
      had_previous_ = true;
      previous_ = current;
    }

    setenv("TZ", zone.c_str(), 1);
    tzset();
  }

  ~ScopedTimeZone() {
    if (had_previous_) {
      setenv("TZ", previous_.c_str(), 1);
    } else {
      unsetenv("TZ");
    }

    tzset();
  }

 private:
  std::string previous_;
  bool had_previous_{false};
};

using UniqueX509 = std::unique_ptr<X509, decltype(&X509_free)>;

/// A certificate carrying nothing but the two validity fields, given as
/// ASN.1 UTCTime or GeneralizedTime strings
UniqueX509 certificateWithValidity(const std::string& not_before,
                                   const std::string& not_after) {
  UniqueX509 cert(X509_new(), X509_free);
  if (cert == nullptr) {
    return cert;
  }

  auto not_before_field = X509_getm_notBefore(cert.get());
  auto not_after_field = X509_getm_notAfter(cert.get());
  if (not_before_field == nullptr || not_after_field == nullptr) {
    return UniqueX509(nullptr, X509_free);
  }

  if (ASN1_TIME_set_string(not_before_field, not_before.c_str()) != 1 ||
      ASN1_TIME_set_string(not_after_field, not_after.c_str()) != 1) {
    return UniqueX509(nullptr, X509_free);
  }

  return cert;
}

} // namespace

class OpensslUtilsTests : public testing::Test {};

// 2030-01-01T00:00:00Z and 2030-07-01T00:00:00Z
TEST_F(OpensslUtilsTests, certificate_validity_is_utc) {
  const std::string kZoneList[] = {
      "UTC", "Asia/Kolkata", "America/Los_Angeles", "Pacific/Kiritimati"};

  for (const auto& zone : kZoneList) {
    ScopedTimeZone scoped_time_zone(zone);

    auto cert = certificateWithValidity("300101000000Z", "300701000000Z");
    ASSERT_NE(cert, nullptr);

    auto opt_not_valid_before = getCertificateNotValidBefore(cert.get());
    ASSERT_TRUE(opt_not_valid_before.has_value()) << "zone: " << zone;
    EXPECT_EQ(opt_not_valid_before.value(), 1893456000) << "zone: " << zone;

    auto opt_not_valid_after = getCertificateNotValidAfter(cert.get());
    ASSERT_TRUE(opt_not_valid_after.has_value()) << "zone: " << zone;
    EXPECT_EQ(opt_not_valid_after.value(), 1909094400) << "zone: " << zone;
  }
}

// 2030-11-03T09:30:00Z falls in the local hour that America/Los_Angeles
// repeats when daylight saving ends, so reading it as local time is
// ambiguous
TEST_F(OpensslUtilsTests, certificate_validity_across_a_dst_transition) {
  ScopedTimeZone scoped_time_zone("America/Los_Angeles");

  auto cert = certificateWithValidity("301103083000Z", "301103093000Z");
  ASSERT_NE(cert, nullptr);

  auto opt_not_valid_before = getCertificateNotValidBefore(cert.get());
  ASSERT_TRUE(opt_not_valid_before.has_value());
  EXPECT_EQ(opt_not_valid_before.value(), 1919925000);

  auto opt_not_valid_after = getCertificateNotValidAfter(cert.get());
  ASSERT_TRUE(opt_not_valid_after.has_value());
  EXPECT_EQ(opt_not_valid_after.value(), 1919928600);
}

// GeneralizedTime, which certificates use from 2050 on
TEST_F(OpensslUtilsTests, certificate_validity_generalized_time) {
  ScopedTimeZone scoped_time_zone("Asia/Kolkata");

  auto cert = certificateWithValidity("20500101000000Z", "20600101000000Z");
  ASSERT_NE(cert, nullptr);

  auto opt_not_valid_before = getCertificateNotValidBefore(cert.get());
  ASSERT_TRUE(opt_not_valid_before.has_value());
  EXPECT_EQ(opt_not_valid_before.value(), 2524608000);

  auto opt_not_valid_after = getCertificateNotValidAfter(cert.get());
  ASSERT_TRUE(opt_not_valid_after.has_value());
  EXPECT_EQ(opt_not_valid_after.value(), 2840140800);
}

} // namespace tables
} // namespace osquery
