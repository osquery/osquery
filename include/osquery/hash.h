/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifdef __APPLE__
  #import <CommonCrypto/CommonDigest.h>
#else
  #include <openssl/sha.h>
  #include <openssl/md5.h>
#endif

#include <string>
#include <iomanip>
#include <sstream>

std::string processHash(unsigned char* hash, unsigned int length);
std::string computeMD5(unsigned char* buffer, long fileLen);
std::string computeSHA1(unsigned char* buffer, long fileLen);
std::string computeSHA256(unsigned char* buffer, long fileLen);