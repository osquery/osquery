/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <vector>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

std::string genKIDProperty(const CFDataRef&);
std::string genCommonNameProperty(const CFDataRef&);
std::string genAlgorithmProperty(const CFDataRef&);

typedef std::string (*PropGenerator)(const CFDataRef&);
typedef std::pair<CFTypeRef, PropGenerator> Property;

extern const std::vector<std::string> kSystemKeychainPaths;
extern const std::vector<std::string> kUserKeychainPaths;
extern const std::map<std::string, Property> kCertificateProperties;

std::string genKIDProperty(const CFDataRef& kid);
std::string genCommonNameProperty(const CFDataRef& ca);
std::string genAlgorithmProperty(const CFDataRef& alg);
std::string genSHA1ForCertificate(const SecCertificateRef& ca);

CFNumberRef CFNumberCreateCopy(const CFNumberRef& number);
CFDataRef CreatePropertyFromCertificate(const SecCertificateRef& cert,
                                        const CFTypeRef& oid);
bool CertificateIsCA(const SecCertificateRef& cert);

// From SecCertificatePriv.h
typedef uint32_t SecKeyUsage;
enum {
  kSecKeyUsageUnspecified = 0,
  kSecKeyUsageDigitalSignature = 1 << 0,
  kSecKeyUsageNonRepudiation = 1 << 1,
  kSecKeyUsageContentCommitment = 1 << 1,
  kSecKeyUsageKeyEncipherment = 1 << 2,
  kSecKeyUsageDataEncipherment = 1 << 3,
  kSecKeyUsageKeyAgreement = 1 << 4,
  kSecKeyUsageKeyCertSign = 1 << 5,
  kSecKeyUsageCRLSign = 1 << 6,
  kSecKeyUsageEncipherOnly = 1 << 7,
  kSecKeyUsageDecipherOnly = 1 << 8,
  kSecKeyUsageCritical = 1 << 31,
  kSecKeyUsageAll = 0x7FFFFFFF
};
}
}
