// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/algorithm/string.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <gtest/gtest.h>

#include <osquery/database.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/core/test_util.h"

using namespace osquery::core;
namespace bai = boost::archive::iterators;

namespace osquery {
namespace tables {

typedef bai::binary_from_base64<const char*> base64_str;
typedef bai::transform_width<base64_str, 8, 6> base64_dec;

bool CertificateIsCA(const SecCertificateRef&);
CFDataRef CreatePropertyFromCertificate(const SecCertificateRef&,
                                        const CFTypeRef&);
std::string genSHA1ForCertificate(const SecCertificateRef&);
std::string genCommonNameProperty(const CFDataRef&);
std::string genKIDProperty(const CFDataRef&);

std::string base64_decode(const std::string& encoded) {
  std::string is;
  std::stringstream os;

  is = encoded;
  boost::replace_all(is, "\r\n", "");
  boost::replace_all(is, "\n", "");
  uint32_t size = is.size();

  // Remove the padding characters
  if (size && is[size - 1] == '=') {
    --size;
    if (size && is[size - 1] == '=') {
      --size;
    }
  }

  if (size == 0) {
    return std::string();
  }

  std::copy(base64_dec(is.data()),
            base64_dec(is.data() + size),
            std::ostream_iterator<char>(os));

  return os.str();
}

class CACertsTests : public ::testing::Test {
 protected:
  virtual void SetUp() {
    std::string raw;
    CFDataRef data;

    raw = base64_decode(getCACertificateContent());
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

TEST_F(CACertsTests, test_certificate_is_ca) {
  EXPECT_EQ(true, CertificateIsCA(cert));
}

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
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
