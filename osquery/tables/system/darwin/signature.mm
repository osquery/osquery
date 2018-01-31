/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iomanip>
#include <sstream>

#include <CommonCrypto/CommonDigest.h>
#include <Foundation/Foundation.h>
#include <Security/CodeSigning.h>

#include <osquery/core.h>
#include <osquery/core/conversions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/tables/system/darwin/keychain.h"

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_signature_defs.hpp>

namespace osquery {
namespace tables {

// Get the flags to pass to SecStaticCodeCheckValidityWithErrors, depending on
// the OS version.
Status getVerifyFlags(SecCSFlags& flags) {
  using boost::lexical_cast;
  using boost::bad_lexical_cast;

  static SecCSFlags sFlags;

  if (sFlags == 0) {
    auto qd = SQL::selectAllFrom("os_version");
    if (qd.size() != 1) {
      return Status(-1, "Couldn't determine OS X version");
    }

    int minorVersion;
    try {
      minorVersion = lexical_cast<int>(qd.front().at("minor"));
    } catch (const bad_lexical_cast& e) {
      return Status(-1, "Couldn't determine OS X version");
    }

    sFlags = kSecCSStrictValidate | kSecCSCheckAllArchitectures;
    if (minorVersion > 8) {
      sFlags |= kSecCSCheckNestedCode;
    }
  }

  flags = sFlags;
  return Status(0, "ok");
}

// Generate a signature for a single file.
void genSignatureForFile(const std::string& path, QueryData& results) {
  Row r;
  OSStatus result;

  // Defaults
  r["path"] = path;
  r["signed"] = INTEGER(0);
  r["identifier"] = "";

  // Get flags for the file.
  SecCSFlags flags = 0;
  if (!getVerifyFlags(flags).ok()) {
    VLOG(1) << "Could not get verify flags";
    return;
  }

  // Create a URL that points to this file.
  auto url = (__bridge CFURLRef)[NSURL fileURLWithPath:@(path.c_str())];
  if (url == nullptr) {
    VLOG(1) << "Could not create URL from file: " << path;
    return;
  }

  // Create the static code object.
  SecStaticCodeRef staticCode = nullptr;
  result = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
  if (result != errSecSuccess || staticCode == nullptr) {
    VLOG(1) << "Could not create static code object for file: " << path;
    return;
  }

  // Actually validate.
  bool isValidated = false;
  result =
      SecStaticCodeCheckValidityWithErrors(staticCode, flags, nullptr, nullptr);
  if (result == errSecSuccess) {
    isValidated = true;
  } else {
    // If this errors, then we either don't have a signature, or it's malformed.
    VLOG(1) << "Static code validity check failed for file: " << path;
  }
  CFDictionaryRef codeInfo = nullptr;
  result = SecCodeCopySigningInformation(
      staticCode, kSecCSSigningInformation | kSecCSRequirementInformation,
      &codeInfo);
  if (result == errSecSuccess) {
    // If we don't get an identifier for this file, then it's not signed.
    CFStringRef ident =
        (CFStringRef)CFDictionaryGetValue(codeInfo, kSecCodeInfoIdentifier);
    if (ident != nullptr) {
      // We have an identifier - this indicates that the file is signed,
      // and, since it didn't error above, it's *also* a valid signature.
      if (isValidated) {
        r["signed"] = INTEGER(1);
      }
      r["identifier"] = stringFromCFString(ident);

      // Get CDHash
      r["cdhash"] = "";
      CFDataRef hashInfo =
          (CFDataRef)CFDictionaryGetValue(codeInfo, kSecCodeInfoUnique);
      if (hashInfo != nullptr) {
        r["cdhash"].reserve(CC_SHA1_DIGEST_LENGTH);
        // Get the SHA-1 bytes
        std::stringstream ss;
        auto bytes = CFDataGetBytePtr(hashInfo);
        if (bytes != nullptr &&
            CFDataGetLength(hashInfo) == CC_SHA1_DIGEST_LENGTH) {
          // Write bytes as hex strings
          for (size_t n = 0; n < CC_SHA1_DIGEST_LENGTH; n++) {
            ss << std::hex << std::setfill('0') << std::setw(2);
            ss << (unsigned int)bytes[n];
          }
          r["cdhash"] = ss.str();
        }
        if (r["cdhash"].length() != CC_SHA1_DIGEST_LENGTH * 2) {
          VLOG(1) << "Error extracting code directory hash";
          r["cdhash"] = "";
        }
      }

      // Team Identifier
      r["team_identifier"] = "";
      CFTypeRef teamIdent = nullptr;
      if (CFDictionaryGetValueIfPresent(codeInfo, kSecCodeInfoTeamIdentifier,
                                        &teamIdent)) {
        r["team_identifier"] = stringFromCFString((CFStringRef)teamIdent);
      }

      // Get common name
      r["authority"] = "";
      CFArrayRef certChain =
          (CFArrayRef)CFDictionaryGetValue(codeInfo, kSecCodeInfoCertificates);
      if (certChain != nullptr && CFArrayGetCount(certChain) > 0) {
        auto cert = SecCertificateRef(CFArrayGetValueAtIndex(certChain, 0));
        auto der_encoded_data = SecCertificateCopyData(cert);
        if (der_encoded_data != nullptr) {
          auto der_bytes = CFDataGetBytePtr(der_encoded_data);
          auto length = CFDataGetLength(der_encoded_data);
          auto x509_cert = d2i_X509(nullptr, &der_bytes, length);
          if (x509_cert != nullptr) {
            std::string subject;
            std::string issuer;
            std::string commonName;
            genCommonName(x509_cert, subject, commonName, issuer);
            r["authority"] = commonName;
            X509_free(x509_cert);
          } else {
            VLOG(1) << "Error decoding DER encoded certificate";
          }
          CFRelease(der_encoded_data);
        }
      }
    } else {
      VLOG(1) << "No identifier found for file: " << path;
    }
    CFRelease(codeInfo);
  } else {
    VLOG(1) << "Could not get signing information for file: " << path;
  }

  results.push_back(r);
  CFRelease(staticCode);
}

QueryData genSignature(QueryContext& context) {
  QueryData results;

  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path", LIKE, paths,
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
  for (const auto& path_string : paths) {
    // Note: we are explicitly *not* using is_regular_file here, since you can
    // pass a directory path to the verification functions (e.g. for app
    // bundles, etc.)
    if (!pathExists(path_string).ok()) {
      continue;
    }

    genSignatureForFile(path_string, results);
  }

  return results;
}
}
}
