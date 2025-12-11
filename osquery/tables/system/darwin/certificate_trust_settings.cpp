/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/darwin/keychain.h>
#include <osquery/utils/conversions/darwin/cfdata.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

#define kSecTrustSettingsPolicyName CFSTR("kSecTrustSettingsPolicyName")

namespace osquery {
namespace tables {

const std::map<std::string, SecTrustSettingsDomain> kSecTrustSettingsDomains = {
    {"admin", kSecTrustSettingsDomainAdmin},
    {"system", kSecTrustSettingsDomainSystem},
    {"user", kSecTrustSettingsDomainUser},
};

void getCertificateTrustSettingsForDomain(std::string domain_name,
                                          SecTrustSettingsDomain domain,
                                          QueryData& results) {
  CFArrayRef certificates;
  OSStatus status = SecTrustSettingsCopyCertificates(domain, &certificates);
  if (status != errSecSuccess) {
    CFStringRef error = SecCopyErrorMessageString(status, nil);
    VLOG(1) << "Failed to copy certificate trust settings for domain: "
            << domain << ". Error: " << error;
    CFRelease(error);
    return;
  }

  CFIndex cert_count = CFArrayGetCount(certificates);
  for (CFIndex i = 0; i < cert_count; i++) {
    Row r;
    r["trust_domain"] = domain_name;
    OSStatus cert_status;
    SecCertificateRef cert =
        (SecCertificateRef)CFArrayGetValueAtIndex(certificates, i);

    CFStringRef common_name = nullptr;
    cert_status = SecCertificateCopyCommonName(cert, &common_name);
    if (common_name) {
      if (cert_status == errSecSuccess) {
        r["common_name"] = stringFromCFString(common_name);
      }
      CFRelease(common_name);
    }

    CFDataRef serial_number = SecCertificateCopySerialNumberData(cert, nil);
    if (serial_number) {
      const UInt8* serial_bytes = CFDataGetBytePtr(serial_number);
      CFIndex serial_length = CFDataGetLength(serial_number);
      std::stringstream ss;
      ss << std::hex << std::uppercase << std::setfill('0');

      for (CFIndex o = 0; o < serial_length; o++) {
        ss << std::setw(2) << static_cast<int>(serial_bytes[o]);
      }

      r["serial"] = ss.str();

      CFRelease(serial_number);
    }

    CFArrayRef trust_settings;
    cert_status =
        SecTrustSettingsCopyTrustSettings(cert, domain, &trust_settings);
    if (cert_status == errSecSuccess && trust_settings) {
      CFIndex trust_settings_count = CFArrayGetCount(trust_settings);
      for (CFIndex o = 0; o < trust_settings_count; o++) {
        CFDictionaryRef trust_setting =
            (CFDictionaryRef)CFArrayGetValueAtIndex(trust_settings, o);

        if (CFDictionaryContainsKey(trust_setting,
                                    kSecTrustSettingsPolicyName)) {
          CFStringRef trust_policy_name;
          trust_policy_name = (CFStringRef)CFDictionaryGetValue(
              trust_setting, kSecTrustSettingsPolicyName);
          r["trust_policy_name"] = stringFromCFString(trust_policy_name);
        }

        if (CFDictionaryContainsKey(trust_setting,
                                    kSecTrustSettingsPolicyString)) {
          CFStringRef trust_policy_data;
          trust_policy_data = (CFStringRef)CFDictionaryGetValue(
              trust_setting, kSecTrustSettingsPolicyString);
          r["trust_policy_data"] = stringFromCFString(trust_policy_data);
        }

        if (CFDictionaryContainsKey(trust_setting,
                                    kSecTrustSettingsAllowedError)) {
          CFDataRef trust_allowed_error;
          uint32_t trust_allowed_error_value;
          trust_allowed_error = (CFDataRef)CFDictionaryGetValue(
              trust_setting, kSecTrustSettingsAllowedError);
          CFNumberGetValue((CFNumberRef)trust_allowed_error,
                           kCFNumberSInt32Type,
                           &trust_allowed_error_value);
          CFStringRef error =
              SecCopyErrorMessageString(trust_allowed_error_value, nil);
          r["trust_allowed_error"] = stringFromCFString(error);
          CFRelease(error);
        }

        if (CFDictionaryContainsKey(trust_setting, kSecTrustSettingsKeyUsage)) {
          CFNumberRef trust_key_usage;
          trust_key_usage = (CFNumberRef)CFDictionaryGetValue(
              trust_setting, kSecTrustSettingsKeyUsage);
          uint32_t trust_key_usage_value;
          if (CFNumberGetValue(trust_key_usage,
                               CFNumberGetType(trust_key_usage),
                               &trust_key_usage_value)) {
            switch (trust_key_usage_value) {
            case kSecTrustSettingsKeyUseSignature:
              r["trust_key_usage"] = "sign_data_verify_signature";
              break;
            case kSecTrustSettingsKeyUseEnDecryptData:
              r["trust_key_usage"] = "encrypt_decrypt_data";
              break;
            case kSecTrustSettingsKeyUseEnDecryptKey:
              r["trust_key_usage"] = "encrypt_decrypt_key";
              break;
            case kSecTrustSettingsKeyUseSignCert:
              r["trust_key_usage"] = "sign_certificate_verify_signature";
              break;
            case kSecTrustSettingsKeyUseSignRevocation:
              r["trust_key_usage"] = "sign_ocsp_crl_verify_signature";
              break;
            case kSecTrustSettingsKeyUseKeyExchange:
              r["trust_key_usage"] = "key_exchange";
              break;
            case kSecTrustSettingsKeyUseAny:
              r["trust_key_usage"] = "any";
              break;
            default:
              r["trust_key_usage"] = "unknown";
              break;
            }
          }
        }

        if (CFDictionaryContainsKey(trust_setting, kSecTrustSettingsResult)) {
          CFNumberRef trust_result;
          trust_result = (CFNumberRef)CFDictionaryGetValue(
              trust_setting, kSecTrustSettingsResult);
          uint32_t trust_result_value;
          if (CFNumberGetValue(trust_result,
                               CFNumberGetType(trust_result),
                               &trust_result_value)) {
            switch (trust_result_value) {
            case kSecTrustSettingsResultInvalid:
              r["trust_result"] = "invalid";
              break;
            case kSecTrustSettingsResultTrustRoot:
              r["trust_result"] = "trusted_root";
              break;
            case kSecTrustSettingsResultTrustAsRoot:
              r["trust_result"] = "trusted_non_root_as_root";
              break;
            case kSecTrustSettingsResultDeny:
              r["trust_result"] = "distrusted";
              break;
            case kSecTrustSettingsResultUnspecified:
              r["trust_result"] = "unspecified";
              break;
            default:
              r["trust_result"] = "unknown";
              break;
            }
          }
        }

        results.push_back(r);
      }

      CFRelease(trust_settings);
    }
  }

  CFRelease(certificates);
}

QueryData genCertificateTrustSettings(QueryContext& context) {
  QueryData results;

  auto domains = context.constraints["trust_domain"].getAll(EQUALS);
  if (!domains.empty()) {
    for (const auto& domain : domains) {
      if (kSecTrustSettingsDomains.count(domain)) {
        getCertificateTrustSettingsForDomain(
            domain, kSecTrustSettingsDomains.at(domain), results);
      } else {
        VLOG(1) << "Unknown trust domain name. Must be one of (admin, system, "
                   "user).";
      }
    }
  } else {
    for (const auto& pair : kSecTrustSettingsDomains) {
      getCertificateTrustSettingsForDomain(pair.first, pair.second, results);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
