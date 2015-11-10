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
#include <Cocoa/Cocoa.h>                /* For NSAppKitVersionNumber */
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

void genSignatureForFile(const std::string& path,
                         QueryData& results) {
  Row r;
  OSStatus result;

  // Defaults
  r["path"] = path;
  r["signed"] = INTEGER(0);
  r["identifier"] = "";

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

  // Set up the flags - some of them aren't present on 10.8.
  SecCSFlags csFlags;
  if (floor(NSAppKitVersionNumber) > NSAppKitVersionNumber10_8) {
    csFlags = kSecCSDefaultFlags | kSecCSCheckNestedCode;
  } else {
    csFlags = kSecCSBasicValidateOnly;
  }

  // Actually validate.
  result = SecStaticCodeCheckValidityWithErrors(staticCode, csFlags, NULL, NULL);
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
