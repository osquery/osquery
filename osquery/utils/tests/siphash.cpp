/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/utils/siphash.h>

namespace osquery {

namespace {

// Digests from the SipHash reference test vectors: the key is the bytes
// 00 01 .. 0f and the input is the bytes 00 01 02 .. of the given length.
const uint64_t kExpected[] = {
    0x726fdb47dd0e0e31ULL,
    0x74f839c593dc67fdULL,
    0x0d6c8009d9a94f5aULL,
    0x85676696d7fb7e2dULL,
    0xcf2794e0277187b7ULL,
    0x18765564cd99a68dULL,
    0xcbc9466e58fee3ceULL,
    0xab0200f58b01d137ULL,
    0x93f5f5799a932462ULL,
    0x9e0082df0ba9e4b0ULL,
    0x7a5dbbc594ddb9f3ULL,
    0xf4b32f46226bada7ULL,
    0x751e8fbc860ee5fbULL,
    0x14ea5627c0843d90ULL,
    0xf723ca908e7af2eeULL,
    0xa129ca6149be45e5ULL,
};

// The key words are the key bytes in little endian order, independent of the
// host byte order.
constexpr uint64_t kKey0 = 0x0706050403020100ULL;
constexpr uint64_t kKey1 = 0x0f0e0d0c0b0a0908ULL;

} // namespace

TEST(SipHash24Tests, reference_vectors) {
  unsigned char input[16];
  for (size_t i = 0; i < sizeof(input); ++i) {
    input[i] = static_cast<unsigned char>(i);
  }

  for (size_t length = 0; length < sizeof(kExpected) / sizeof(kExpected[0]);
       ++length) {
    SipHash24 hash(kKey0, kKey1);
    hash.update(input, length);
    EXPECT_EQ(hash.digest(), kExpected[length]) << "input length " << length;
  }
}

TEST(SipHash24Tests, input_split_across_updates) {
  // The input 00 01 .. 14, length 21, split into two update() calls.
  unsigned char input[21];
  for (size_t i = 0; i < sizeof(input); ++i) {
    input[i] = static_cast<unsigned char>(i);
  }

  SipHash24 split(kKey0, kKey1);
  split.update(input, 9);
  split.update(input + 9, 12);
  EXPECT_EQ(split.digest(), 0xd0f2cbb02e3b67c7ULL);

  SipHash24 whole(kKey0, kKey1);
  whole.update(input, 21);
  EXPECT_EQ(whole.digest(), split.digest());
}

TEST(SipHash24Tests, different_keys_differ) {
  const char* input = "some untrusted input";
  SipHash24 first(0, 0);
  first.update(input, 19);
  SipHash24 second(1, 0);
  second.update(input, 19);
  EXPECT_NE(first.digest(), second.digest());
}

} // namespace osquery
