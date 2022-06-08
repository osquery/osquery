/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <sstream>

#include <CommonCrypto/CommonDigest.h>
#include <Foundation/Foundation.h>
#include <Security/CodeSigning.h>

#include <osquery/core/core.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/darwin/keychain.h>
#include <osquery/tables/system/posix/openssl_utils.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/expected/expected.h>

#include <openssl/x509.h>

namespace osquery {
namespace tables {

// Empty string runs default verification on a file
// TODO: we may want to eventually add arm64e to this set. As of October 2021,
// arm64 and arm64e are aliased and duplicated results are returned.
std::set<std::string> kCheckedArches{
    "", "i386", "ppc", "arm", "x86_64", "arm64"};

// Get the flags to pass to SecStaticCodeCheckValidityWithErrors, depending on
// the OS version.
Status getVerifyFlags(SecCSFlags& flags, bool hashResources) {
  flags = kSecCSStrictValidate | kSecCSCheckAllArchitectures |
          kSecCSCheckNestedCode;

  if (!hashResources) {
    flags |= kSecCSDoNotValidateResources;
  }

  return Status(0, "ok");
}

Status genSignatureForFileAndArch(const std::string& path,
                                  const std::string& arch,
                                  bool hashResources,
                                  QueryData& results) {
  OSStatus result;
  SecStaticCodeRef static_code = nullptr;

  // Create a URL that points to this file.
  auto url = (__bridge CFURLRef)[NSURL fileURLWithPath:@(path.c_str())];
  if (url == nullptr) {
    return Status(1, "Could not create URL from file");
  }

  if (arch.empty()) {
    // Create the static code object.
    result = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &static_code);
    if (result != errSecSuccess) {
      if (static_code != nullptr) {
        CFRelease(static_code);
      }
      return Status(1, "Could not create static code object");
    }
  } else {
    CFMutableDictionaryRef context =
        CFDictionaryCreateMutable(nullptr,
                                  0,
                                  &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
    auto cfkey = CFStringCreateWithCString(
        kCFAllocatorDefault, arch.c_str(), kCFStringEncodingUTF8);
    CFDictionaryAddValue(context, kSecCodeAttributeArchitecture, cfkey);
    CFRelease(cfkey);
    result = SecStaticCodeCreateWithPathAndAttributes(
        url, kSecCSDefaultFlags, context, &static_code);
    CFRelease(context);
    if (result != errSecSuccess) {
      if (static_code != nullptr) {
        CFRelease(static_code);
      }
      return Status(0, "No code to verify");
    }
  }

  Row r;
  r["path"] = path;
  r["hash_resources"] = INTEGER(hashResources);
  r["arch"] = arch;
  r["identifier"] = "";

  SecCSFlags flags = 0;
  getVerifyFlags(flags, hashResources);
  result = SecStaticCodeCheckValidityWithErrors(
      static_code, flags, nullptr, nullptr);
  if (result == errSecSuccess) {
    r["signed"] = "1";
  } else {
    // If this errors, then we either don't have a signature, or it's malformed.
    r["signed"] = "0";
  }

  CFDictionaryRef code_info = nullptr;
  result = SecCodeCopySigningInformation(
      static_code,
      kSecCSSigningInformation | kSecCSRequirementInformation,
      &code_info);

  if (result != errSecSuccess) {
    results.push_back(r);
    CFRelease(static_code);

    if (code_info != nullptr) {
      CFRelease(code_info);
    }
    return Status(1, "Could not get signing information for file");
  }

  // If we don't get an identifier for this file, then it's not signed.
  CFStringRef ident =
      (CFStringRef)CFDictionaryGetValue(code_info, kSecCodeInfoIdentifier);

  if (ident == nullptr) {
    results.push_back(r);
    CFRelease(code_info);
    CFRelease(static_code);
    return Status(1, "No identifier found for arch: " + arch);
  }

  r["identifier"] = stringFromCFString(ident);

  // Get CDHash
  r["cdhash"] = "";
  CFDataRef hashInfo =
      (CFDataRef)CFDictionaryGetValue(code_info, kSecCodeInfoUnique);
  if (hashInfo != nullptr) {
    // Get the CDHash bytes
    std::stringstream ss;
    auto bytes = CFDataGetBytePtr(hashInfo);
    auto bytes_length = static_cast<size_t>(CFDataGetLength(hashInfo));
    if (bytes != nullptr && bytes_length > 0) {
      // Write bytes as hex strings
      for (size_t n = 0; n < bytes_length; n++) {
        ss << std::hex << std::setfill('0') << std::setw(2);
        ss << (unsigned int)bytes[n];
      }
      r["cdhash"] = ss.str();
    }
    if (r["cdhash"].length() != bytes_length * 2) {
      VLOG(1) << "Error extracting code directory hash";
      r["cdhash"] = "";
    }
  }

  // Team Identifier
  r["team_identifier"] = "";
  CFTypeRef team_ident = nullptr;
  if (CFDictionaryGetValueIfPresent(
          code_info, kSecCodeInfoTeamIdentifier, &team_ident)) {
    if (CFGetTypeID(team_ident) == CFStringGetTypeID()) {
      r["team_identifier"] = stringFromCFString((CFStringRef)team_ident);
    } else {
      VLOG(1) << "Team identifier was not a string";
    }
  }

  // Get common name
  r["authority"] = "";
  CFArrayRef certChain =
      (CFArrayRef)CFDictionaryGetValue(code_info, kSecCodeInfoCertificates);
  if (certChain != nullptr && CFArrayGetCount(certChain) > 0) {
    auto cert = SecCertificateRef(CFArrayGetValueAtIndex(certChain, 0));
    auto der_encoded_data = SecCertificateCopyData(cert);
    if (der_encoded_data != nullptr) {
      auto der_bytes = CFDataGetBytePtr(der_encoded_data);
      auto length = CFDataGetLength(der_encoded_data);
      auto x509_cert = d2i_X509(nullptr, &der_bytes, length);
      if (x509_cert != nullptr) {
        auto opt_common_name = getCertificateCommonName(x509_cert);
        r["authority"] = SQL_TEXT(opt_common_name.value_or(""));
        X509_free(x509_cert);
      } else {
        VLOG(1) << "Error decoding DER encoded certificate";
      }
      CFRelease(der_encoded_data);
    }
  }

  results.push_back(r);
  CFRelease(static_code);
  CFRelease(code_info);
  return Status(0);
}

// Generate a signature for a single file.
void genSignatureForFile(const std::string& path,
                         bool hashResources,
                         QueryData& results) {
  for (const auto& arch : kCheckedArches) {
    // This returns a status but there is nothing we need to handle
    // here so we can safely ignore it
    genSignatureForFileAndArch(path, arch, hashResources, results);
  }
}

QueryData genSignature(QueryContext& context) {
  QueryData results;

  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  auto hashResContraints = context.constraints["hash_resources"].getAll(EQUALS);
  if (hashResContraints.size() > 1) {
    VLOG(1) << "Received multiple constraint values for column hash_resources. "
               "Only the first one will be evaluated.";
  }

  bool hashResources = true;
  if (!hashResContraints.empty()) {
    const auto& value = *hashResContraints.begin();
    hashResources = (value != "0");
  }

  @autoreleasepool {
    for (const auto& path_string : paths) {
      // Note: we are explicitly *not* using is_regular_file here, since you can
      // pass a directory path to the verification functions (e.g. for app
      // bundles, etc.)
      if (!pathExists(path_string).ok()) {
        continue;
      }
      genSignatureForFile(path_string, hashResources, results);
    }
  }

  return results;
}
}
}
