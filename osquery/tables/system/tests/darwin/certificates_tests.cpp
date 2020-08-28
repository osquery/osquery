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

#include <osquery/logger/logger.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/darwin/keychain.h>
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
  std::string sha1;
  sha1 = genSHA1ForCertificate(x_cert);

  EXPECT_EQ("f149bae28e3c754ff4bb062b2c1b8bac81b8783e", sha1);
}

TEST_F(CACertsTests, test_certificate_properties) {
  std::string subject, common_name, issuer;
  genCommonName(x_cert, subject, common_name, issuer);
  EXPECT_EQ("localhost.localdomain", common_name);

  X509_check_ca(x_cert);

// Temporary workaround for Buck compiling with an older openssl version
#if OPENSSL_VERSION_NUMBER < 0x10101000L
  const auto* subject_key_id = x_cert->skid;

  ASSERT_NE(subject_key_id, nullptr);

  auto skid = genKIDProperty(subject_key_id->data, subject_key_id->length);
#else
  const auto* subject_key_id = X509_get0_subject_key_id(x_cert);

  ASSERT_NE(subject_key_id, nullptr);

  auto skid = genKIDProperty(subject_key_id->data, subject_key_id->length);
#endif

  EXPECT_EQ("f2b99b00e0ee60d57c426ce3e64e3fdc6f6411c0", skid);

  auto not_before = std::to_string(genEpoch(X509_get_notBefore(x_cert)));
  EXPECT_EQ("1408475536", not_before);

  auto ca = (CertificateIsCA(x_cert)) ? "1" : "0";
  EXPECT_EQ("1", ca);
}
} // namespace tables
} // namespace osquery
