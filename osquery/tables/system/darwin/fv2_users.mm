/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#import <dlfcn.h>
#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

QueryData genFV2Users(QueryContext& context) {
  @autoreleasepool {

    QueryData results;
    
    void *libCoreStorageHandle = dlopen("libCoreStorage.dylib", RTLD_LOCAL | RTLD_LAZY);
    if (!libCoreStorageHandle) {
        return results;
    }
    
    typedef CFDictionaryRef (*CoreStorageCopyFamilyPropertiesForMount_t)(const char *);
    CoreStorageCopyFamilyPropertiesForMount_t CoreStorageCopyFamilyPropertiesForMount =
    (CoreStorageCopyFamilyPropertiesForMount_t) dlsym(libCoreStorageHandle, "CoreStorageCopyFamilyPropertiesForMount");
    if (!CoreStorageCopyFamilyPropertiesForMount) {
        return results;
    }
    
    NSDictionary *properties = (__bridge NSDictionary *)CoreStorageCopyFamilyPropertiesForMount("/");
    for (NSDictionary *user in properties[@"com.apple.corestorage.lvf.encryption.context"][@"CryptoUsers"]) {
        if (![user[@"UserNamesData"] isKindOfClass:[NSArray class]]) {
            continue;
        }
        Row r;
        NSString *userShortName = [[NSString alloc] initWithData:[user[@"UserNamesData"] lastObject]
                                                        encoding:NSUTF8StringEncoding];
        r["user"] = TEXT([userShortName UTF8String]);
        results.push_back(r);
    }
    
    return results;

  }
}
}
}
