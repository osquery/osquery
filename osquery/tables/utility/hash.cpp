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
#include <iomanip>

#include <boost/filesystem.hpp>
#include <boost/uuid/sha1.hpp>

#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

std::string processHash(unsigned char* hash, unsigned int length){
    std::stringstream ss;
    for(int i = 0; i < length; i++){
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string computeMD5(unsigned char* buffer, long fileLen){
    #ifdef __APPLE__
      const unsigned int LENGTH = CC_MD5_DIGEST_LENGTH;
      unsigned char hash[LENGTH];
      CC_MD5_CTX md5;
      CC_MD5_Init(&md5);
      CC_MD5_Update(&md5, buffer, fileLen);
      CC_MD5_Final(hash, &md5);
    #else
      const unsigned int LENGTH = MD5_DIGEST_LENGTH;
      unsigned char hash[LENGTH];
      MD5_CTX md5;
      MD5_Init(&md5);
      MD5_Update(&md5, buffer, fileLen);
      MD5_Final(hash, &md5);
    #endif
    
    return processHash(hash, LENGTH);
}

std::string computeSHA1(unsigned char* buffer, long fileLen){
    #ifdef __APPLE__
      const unsigned int LENGTH = CC_SHA1_DIGEST_LENGTH;
      unsigned char hash[LENGTH];
      CC_SHA1_CTX sha1;
      CC_SHA1_Init(&sha1);
      CC_SHA1_Update(&sha1, buffer, fileLen);
      CC_SHA1_Final(hash, &sha1);
    #else
      const unsigned int LENGTH = SHA_DIGEST_LENGTH;
      unsigned char hash[LENGTH];
      SHA_CTX sha1;
      SHA1_Init(&sha1);
      SHA1_Update(&sha1, buffer, fileLen);
      SHA1_Final(hash, &sha1);
    #endif
    return processHash(hash, LENGTH);
}
std::string computeSHA256(unsigned char* buffer, long fileLen){
    #ifdef __APPLE__
      const unsigned int LENGTH = CC_SHA256_DIGEST_LENGTH;
      unsigned char hash[LENGTH];
      CC_SHA256_CTX sha256;
      CC_SHA256_Init(&sha256);
      CC_SHA256_Update(&sha256, buffer, fileLen);
      CC_SHA256_Final(hash, &sha256);
    #else
      const unsigned int LENGTH = SHA256_DIGEST_LENGTH;
      unsigned char hash[LENGTH];
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, buffer, fileLen);
      SHA256_Final(hash, &sha256);
    #endif
    return processHash(hash, LENGTH);
}

void computeAllHashes(Row& r, const std::string& content, long filelen){
    r["md5"]        = computeMD5(   (unsigned char *)content.c_str(), filelen);
    r["sha1"]       = computeSHA1(  (unsigned char *)content.c_str(), filelen);
    r["sha256"]     = computeSHA256((unsigned char *)content.c_str(), filelen);
}

QueryData genHash(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path)) {
      continue;
    }
    std::string content;
    auto s = osquery::readFile(path.string(), content);
    long filelen = (long)content.length();
    Row r;
    r["path"]       = path.string();
    r["directory"]  = path.parent_path().string();
    computeAllHashes(r, content, filelen);
    results.push_back(r);
  }

  auto directories = context.constraints["directory"].getAll(EQUALS);
  for (const auto& directory_string : directories) {
    boost::filesystem::path directory = directory_string;
    if (!boost::filesystem::is_directory(directory)) {
      continue;
    }

    // Iterate over the directory and generate a hash for each regular file.
    boost::filesystem::directory_iterator begin(directory), end;
    for (; begin != end; ++begin) {
      Row r;
      r["path"] = begin->path().string();
      r["directory"] = directory_string;
      if (boost::filesystem::is_regular_file(begin->status())) {
        std::string content;
        auto s = osquery::readFile(begin->path().string(), content);
        computeAllHashes(r, content, content.length());
      }
      results.push_back(r);
    }
  }

  return results;
}
}
}
