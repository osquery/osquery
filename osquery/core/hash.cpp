/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 #include <osquery/hash.h>
 
namespace osquery{

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
}