/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <osquery/logger/logger.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/darwin/keychain.h>
#include <osquery/tables/system/posix/openssl_utils.h>
#include <osquery/utils/base64.h>

namespace osquery {
namespace tables {

// generate content for a PEM-encoded certificate
static std::string getCACertificateContent() {
  std::string content;
  readFile(getTestConfigDirectory() / "test_cert.pem", content);
  return content;
}

class CACertsTests : public ::testing::Test {
 protected:
  virtual void SetUp() {
    std::string raw;
    CFDataRef data;

    raw = base64::decode(getCACertificateContent());
    data =
        CFDataCreate(nullptr, (const UInt8*)raw.c_str(), (CFIndex)raw.size());
    cert = SecCertificateCreateWithData(nullptr, data);
    cert_der_data = SecCertificateCopyData(cert);
    auto bytes = CFDataGetBytePtr(cert_der_data);
    x_cert = d2i_X509(nullptr, &bytes, CFDataGetLength(cert_der_data));

    CFRelease(data);
  }

  virtual void TearDown() {
    if (cert != nullptr) {
      CFRelease(cert);
    }
    if (cert_der_data != nullptr) {
      CFRelease(cert_der_data);
    }
    if (x_cert != nullptr) {
      X509_free(x_cert);
    }
  }

  SecCertificateRef cert;
  CFDataRef cert_der_data;
  X509* x_cert;
};

TEST_F(CACertsTests, test_certificate_sha1) {
  auto opt_digest = generateCertificateSHA1Digest(x_cert);
  ASSERT_TRUE(opt_digest.has_value());

  EXPECT_EQ("f149bae28e3c754ff4bb062b2c1b8bac81b8783e", opt_digest.value());
}

TEST_F(CACertsTests, test_certificate_properties) {
  auto opt_issuer_name = getCertificateIssuerName(x_cert, true);
  EXPECT_TRUE(opt_issuer_name.has_value());

  opt_issuer_name = getCertificateIssuerName(x_cert, false);
  EXPECT_TRUE(opt_issuer_name.has_value());

  auto opt_subject_name = getCertificateSubjectName(x_cert, true);
  EXPECT_TRUE(opt_subject_name.has_value());

  opt_subject_name = getCertificateSubjectName(x_cert, false);
  EXPECT_TRUE(opt_subject_name.has_value());

  auto opt_common_name = getCertificateCommonName(x_cert);
  ASSERT_TRUE(opt_common_name.has_value());
  EXPECT_EQ("localhost.localdomain", opt_common_name.value());

  auto opt_subject_key_id = getCertificateSubjectKeyID(x_cert);
  ASSERT_TRUE(opt_subject_key_id.has_value());
  EXPECT_EQ("f2b99b00e0ee60d57c426ce3e64e3fdc6f6411c0",
            opt_subject_key_id.value());

  auto opt_not_valid_before = getCertificateNotValidBefore(x_cert);
  ASSERT_TRUE(opt_not_valid_before.has_value());
  EXPECT_EQ(1408475536, opt_not_valid_before.value());

  bool is_ca{};
  bool is_self_signed{};
  getCertificateAttributes(x_cert, is_ca, is_self_signed);
  EXPECT_TRUE(is_ca);
}
} // namespace tables
} // namespace osquery
