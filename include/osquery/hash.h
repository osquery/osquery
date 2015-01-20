/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

namespace osquery {

// osquery-supported hash function types.
enum HashType {
  HASH_TYPE_MD5 = 2,
  HASH_TYPE_SHA1 = 4,
  HASH_TYPE_SHA256 = 8,
};

class Hash {
 public:
  Hash(HashType algorithm) {
    algorithm_ = algorithm;
    init();
  }

  ~Hash();

  void update(void* buffer, size_t size);
  std::string digest();

 private:
  void init();
  HashType algorithm_;
  void* ctx_;
  size_t length_;
};

/**
 * @brief Compute a hash digest from an already allocated buffer.
 *
 * @param hash_type The osquery-supported hash algorithm.
 * @param buffer A caller-controlled buffer.
 * @param size The length of buffer in bytes.
 * @return A string (hex) representation of the hash digest.
 */
std::string hashFromBuffer(HashType hash_type, void* buffer, size_t size);

/**
 * @brief Compute a hash digest from the file content at a path.
 *
 *
 * @param hash_type The osquery-supported hash algorithm.
 * @param path Filesystem path, the hash target.
 * @return A string (hex) representation of the hash digest.
 */
std::string hashFromFile(HashType hash_type, const std::string& path);
}
