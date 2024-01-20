/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "system_profiler.h"

#include <memory>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/scope_guard.h>

#import <AppKit/NSDocument.h>
#include <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach_error.h>

@interface SPDocument : NSDocument {
}
- (NSMutableDictionary*)reportForDataType:(NSString*)datatype;
@end

namespace osquery {

Status getSystemProfilerReport(const std::string& datatype,
                               NSDictionary*& result) {
  // BEWARE: Because of the dynamic nature of the calls in this function, we
  // must be careful to properly clean up the memory. Any future modifications
  // to this function should attempt to ensure there are no leaks (and test
  // with ./tools/analysis/profile.py --leaks).
  CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/PrivateFrameworks/SPSupport.framework"),
      kCFURLPOSIXPathStyle,
      true);

  if (bundle_url == nullptr) {
    return Status::failure("Error parsing SPSupport bundle URL");
  }

  CFBundleRef bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
  CFRelease(bundle_url);
  if (bundle == nullptr) {
    return Status::failure("Error opening SPSupport bundle");
  }

  auto cleanup_bundle = scope_guard::create([&]() {
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  });

  if (!CFBundleLoadExecutable(bundle)) {
    return Status::failure("SPSupport load executable failed");
  }

#pragma clang diagnostic push
// We are silencing here because we don't know the selector beforehand
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

  id cls = NSClassFromString(@"SPDocument");
  if (cls == nullptr) {
    return Status::failure("Could not load SPDocument class");
  }

  SEL sel = @selector(new);
  if (![cls respondsToSelector:sel]) {
    return Status::failure("SPDocument does not respond to new selector");
  }

  id document = [cls performSelector:sel];
  if (document == nullptr) {
    return Status::failure("[SPDocument new] returned null");
  }

  auto cleanup_document =
      scope_guard::create([&]() { CFRelease((__bridge CFTypeRef)document); });

#pragma clang diagnostic pop

  result = [document
      reportForDataType:[NSString stringWithUTF8String:datatype.c_str()]];

  return Status::success();
}

} // namespace osquery
