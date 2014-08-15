/*
 * Copyright (c) 2014 Petroules Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 *FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import <Foundation/Foundation.h>
#import <TargetConditionals.h>
#import <AvailabilityMacros.h>

#if (defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE) || \
    (defined(MAC_OS_X_VERSION_MAX_ALLOWED) &&          \
     MAC_OS_X_VERSION_MAX_ALLOWED >= 1060)
#import <Availability.h>
#endif

#import "PECocoaBackportsGlobal.h"

#if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
#if __IPHONE_OS_VERSION_MAX_ALLOWED < 80000
#ifndef DECLARE_OPERATING_SYSTEM_VERSION
#define DECLARE_OPERATING_SYSTEM_VERSION 1
#endif
#endif
#if __IPHONE_OS_VERSION_MIN_REQUIRED < 80000
#ifndef LOAD_OPERATING_SYSTEM_VERSION
#define LOAD_OPERATING_SYSTEM_VERSION 1
#endif
#endif
#elif defined(TARGET_OS_MAC) && TARGET_OS_MAC
#if __MAC_OS_X_VERSION_MAX_ALLOWED < 101000
#ifndef DECLARE_OPERATING_SYSTEM_VERSION
#define DECLARE_OPERATING_SYSTEM_VERSION 1
#endif
#endif
#if __MAC_OS_X_VERSION_MIN_REQUIRED < 101000
#ifndef LOAD_OPERATING_SYSTEM_VERSION
#define LOAD_OPERATING_SYSTEM_VERSION 1
#endif
#endif
#endif

#ifndef DECLARE_OPERATING_SYSTEM_VERSION
#define DECLARE_OPERATING_SYSTEM_VERSION 0
#endif

#ifndef LOAD_OPERATING_SYSTEM_VERSION
#define LOAD_OPERATING_SYSTEM_VERSION 0
#endif

#if DECLARE_OPERATING_SYSTEM_VERSION
typedef struct {
  NSInteger majorVersion;
  NSInteger minorVersion;
  NSInteger patchVersion;
} NSOperatingSystemVersion;
#endif

@interface NSProcessInfo (PECocoaBackports)

#if DECLARE_OPERATING_SYSTEM_VERSION
- (NSOperatingSystemVersion)operatingSystemVersion NS_AVAILABLE(10_5, 2_0);
- (BOOL)isOperatingSystemAtLeastVersion:
        (NSOperatingSystemVersion)version NS_AVAILABLE(10_5, 2_0);
#endif

@end