/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <boost/noncopyable.hpp>

namespace osquery {

/**
 * @brief The supported hashing algorithms in osquery
 *
 * These are usually used as a constructor argument to osquery::Hash
 */
enum HashType {
  HASH_TYPE_MD5 = 2,
  HASH_TYPE_SHA1 = 4,
  HASH_TYPE_SHA256 = 8,
};

/**
 * @brief The supported hashing algorithms in osquery
 *
 * These are usually used as a constructor argument to osquery::Hash
 */
enum HashEncodingType {
  HASH_ENCODING_TYPE_HEX = 2,
  HASH_ENCODING_TYPE_BASE64 = 4,
};

/// A result structure for multiple hash requests.
struct MultiHashes {
  int mask;
  std::string md5;
  std::string sha1;
  std::string sha256;
};

/**
 * @brief Hash is a general utility class for hashing content
 *
 * @code{.cpp}
 *   Hash my_hash(HASH_TYPE_SHA256);
 *   my_hash.update(my_buffer, my_buffer_size);
 *   std::cout << my_hash.digest();
 * @endcode
 *
 */
class Hash : private boost::noncopyable {
 public:
  /**
   * @brief Hash constructor
   *
   * The hash class should be initialized with one of osquery::HashType as a
   * constructor argument. The Hash will be initialized with hex encoding.
   *
   * @param algorithm The hashing algorithm which will be used to compute the
   * hash
   */
  explicit Hash(HashType algorithm);

  /**
   * @brief Hash constructor
   *
   * Initialize the Hash class with a HashType and HashEncodingType.
   *
   * @param algorithm The hashing algorithm which will be used to compute the
   * hash
   * @param encoding The encoding that will be used to render the hash digest.
   */
  explicit Hash(HashType algorithm, HashEncodingType encoding);

  /**
   * @brief Hash destructor
   */
  ~Hash();

  /**
   * @brief Update the internal context buffer with additional content
   *
   * This method allows you to chunk up large content so that it doesn't all
   * have to be loaded into memory at the same time
   *
   * @param buffer The buffer to be hashed
   * @param size The size of the buffer to be hashed
   */
  void update(const void* buffer, size_t size);

  /**
   * @brief Compute the final hash and return it's result
   *
   * @return The final hash value
   */
  std::string digest();

 private:
  /**
   * @brief Private default constructor
   *
   * The osquery::Hash class should only ever be instantiated with a HashType
   */
  Hash(){};

 private:
  /// The hashing algorithm which is used to compute the hash
  HashType algorithm_;

  /// The encoding type used to encode the digest.
  HashEncodingType encoding_;

  /// The buffer used to maintain the context and state of the hashing
  /// operations
  void* ctx_;

  /// The length of the hash to be returned
  size_t length_;
};

/**
 * @brief Compute a hash digest from the file content at a path.
 *
 * @param hash_type The osquery-supported hash algorithm.
 * @param path Filesystem path (the hash target).
 * @return A string (hex) representation of the hash digest.
 */
std::string hashFromFile(HashType hash_type, const std::string& path);

/**
 * @brief Compute multiple hashes from a files contents simultaneously.
 *
 * @param mask Bitmask specifying target osquery-supported algorithms.
 * @param path Filesystem path (the hash target).
 * @return A struct containing string (hex) representations
 *         of the hash digests.
 */
MultiHashes hashMultiFromFile(int mask, const std::string& path);

/**
 * @brief Compute a hash digest from the contents of a buffer.
 *
 * @param hash_type The osquery-supported hash algorithm.
 * @param buffer A caller-controlled buffer (already allocated).
 * @param size The length of buffer in bytes.
 * @return A string (hex) representation of the hash digest.
 */
std::string hashFromBuffer(HashType hash_type, const void* buffer, size_t size);
} // namespace osquery
