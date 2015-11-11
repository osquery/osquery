/*
 *  Copyright (c) 2015, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem.hpp>
#include <Foundation/Foundation.h>
#include <Security/CodeSigning.h>

#include <osquery/core.h>
#include <osquery/core/conversions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

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

    sFlags = kSecCSDefaultFlags |  kSecCSCheckAllArchitectures;
    if (minorVersion > 8) {
      sFlags |= kSecCSCheckNestedCode;
    }
  }

  flags = sFlags;
  return Status(0, "ok");
}

// Generate a signature for a single file.
void genSignatureForFile(const std::string& path,
                         QueryData& results) {
  Row r;
  OSStatus result;

  // Defaults
  r["path"] = path;
  r["signed"] = INTEGER(0);
  r["identifier"] = "";

  // Get flags for the file.
  SecCSFlags flags;
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
  SecStaticCodeRef staticCode;
  result = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
  if (result != 0) {
    VLOG(1) << "Could not create static code object for file: " << path;
    return;
  }

  // Actually validate.
  result = SecStaticCodeCheckValidityWithErrors(staticCode, flags, NULL, NULL);
  if (result == 0) {
    CFDictionaryRef codeInfo;

    result = SecCodeCopySigningInformation(
      staticCode,
      kSecCSSigningInformation | kSecCSRequirementInformation,
      &codeInfo);
    if (result == 0) {
      // If we don't get an identifier for this file, then it's not signed.
      CFStringRef ident = (CFStringRef)CFDictionaryGetValue(codeInfo, kSecCodeInfoIdentifier);
      if (ident != nullptr) {
        // We have an identifier - this indicates that the file is signed, and, since
        // it didn't error above, it's *also* a valid signature.
        r["signed"] = INTEGER(1);
        r["identifier"] = stringFromCFString(ident);

        // TODO(andrew-d): can get more information from the signature here?
      } else {
        VLOG(1) << "No identifier found for file: " << path;
      }

      CFRelease(codeInfo);
    } else {
      VLOG(1) << "Could not get signing information for file: " << path;
    }
  } else {
    // If this errors, then we either don't have a signature, or it's malformed.
    VLOG(1) << "Static code validity check failed for file: " << path;
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
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;

    // Note: we are explicitly *not* using is_regular_file here, since you can
    // pass a directory path to the verification functions (e.g. for app
    // bundles, etc.)
    if (!pathExists(path).ok()) {
      continue;
    }

    genSignatureForFile(path_string, results);
  }

  return results;
}
}
}
