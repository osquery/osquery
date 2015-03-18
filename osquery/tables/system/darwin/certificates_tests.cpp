/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/database.h>
#include <osquery/logger.h>

#include "osquery/tables/system/darwin/keychain.h"
#include "osquery/core/test_util.h"

namespace osquery {
namespace tables {

class CACertsTests : public ::testing::Test {
 protected:
  virtual void SetUp() {
    std::string raw;
    CFDataRef data;

    raw = base64Decode(getCACertificateContent());
    data = CFDataCreate(NULL, (const UInt8*)raw.c_str(), (CFIndex)raw.size());
    cert = SecCertificateCreateWithData(NULL, data);
    CFRelease(data);
  }

  virtual void TearDown() {
    if (cert != NULL) {
      CFRelease(cert);
    }
  }

  SecCertificateRef cert;
};

TEST_F(CACertsTests, test_certificate_sha1) {
  std::string sha1;
  sha1 = genSHA1ForCertificate(cert);

  EXPECT_EQ("f149bae28e3c754ff4bb062b2c1b8bac81b8783e", sha1);
}

TEST_F(CACertsTests, test_certificate_properties) {
  CFDataRef property;
  CFTypeRef oid;
  std::string prop_string;

  oid = kSecOIDCommonName;
  property = CreatePropertyFromCertificate(cert, oid);
  prop_string = genCommonNameProperty(property);

  EXPECT_EQ("localhost.localdomain", prop_string);
  CFRelease(property);

  oid = kSecOIDSubjectKeyIdentifier;
  property = CreatePropertyFromCertificate(cert, oid);
  prop_string = genKIDProperty(property);

  EXPECT_EQ("f2b99b00e0ee60d57c426ce3e64e3fdc6f6411c0", prop_string);
  CFRelease(property);

  oid = kSecOIDX509V1ValidityNotBefore;
  property = CreatePropertyFromCertificate(cert, oid);
  prop_string = stringFromCFNumber(property);

  EXPECT_EQ("430168336", prop_string);
  CFRelease(property);

  oid = kSecOIDBasicConstraints;
  property = CreatePropertyFromCertificate(cert, oid);
  prop_string = genCAProperty(property);

  EXPECT_EQ("1", prop_string);
  CFRelease(property);
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
