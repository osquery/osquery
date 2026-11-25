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
    0x726fdb47dd0e0e31ULL, 0x74f839c593dc67fdULL, 0x0d6c8009d9a94f5aULL,
    0x85676696d7fb7e2dULL, 0xcf2794e0277187b7ULL, 0x18765564cd99a68dULL,
    0xcbc9466e58fee3ceULL, 0xab0200f58b01d137ULL, 0x93f5f5799a932462ULL,
    0x9e0082df0ba9e4b0ULL, 0x7a5dbbc594ddb9f3ULL, 0xf4b32f46226bada7ULL,
    0x751e8fbc860ee5fbULL, 0x14ea5627c0843d90ULL, 0xf723ca908e7af2eeULL,
    0xa129ca6149be45e5ULL, 0x3f2acc7f57c29bdbULL, 0x699ae9f52cbe4794ULL,
    0x4bc1b3f0968dd39cULL, 0xbb6dc91da77961bdULL, 0xbed65cf21aa2ee98ULL,
    0xd0f2cbb02e3b67c7ULL, 0x93536795e3a33e88ULL, 0xa80c038ccd5ccec8ULL,
    0xb8ad50c6f649af94ULL, 0xbce192de8a85b8eaULL, 0x17d835b85bbb15f3ULL,
    0x2f2e6163076bcfadULL, 0xde4daaaca71dc9a5ULL, 0xa6a2506687956571ULL,
    0xad87a3535c49ef28ULL, 0x32d892fad841c342ULL, 0x7127512f72f27cceULL,
    0xa7f32346f95978e3ULL, 0x12e0b01abb051238ULL, 0x15e034d40fa197aeULL,
    0x314dffbe0815a3b4ULL, 0x027990f029623981ULL, 0xcadcd4e59ef40c4dULL,
    0x9abfd8766a33735cULL, 0x0e3ea96b5304a7d0ULL, 0xad0c42d6fc585992ULL,
    0x187306c89bc215a9ULL, 0xd4a60abcf3792b95ULL, 0xf935451de4f21df2ULL,
    0xa9538f0419755787ULL, 0xdb9acddff56ca510ULL, 0xd06c98cd5c0975ebULL,
    0xe612a3cb9ecba951ULL, 0xc766e62cfcadaf96ULL, 0xee64435a9752fe72ULL,
    0xa192d576b245165aULL, 0x0a8787bf8ecb74b2ULL, 0x81b3e73d20b49b6fULL,
    0x7fa8220ba3b2eceaULL, 0x245731c13ca42499ULL, 0xb78dbfaf3a8d83bdULL,
    0xea1ad565322a1a0bULL, 0x60e61c23a3795013ULL, 0x6606d7e446282b93ULL,
    0x6ca4ecb15c5f91e1ULL, 0x9f626da15c9625f3ULL, 0xe51b38608ef25f57ULL,
    0x958a324ceb064572ULL,
};

// The key words are the key bytes in little endian order, independent of the
// host byte order.
constexpr uint64_t kKey0 = 0x0706050403020100ULL;
constexpr uint64_t kKey1 = 0x0f0e0d0c0b0a0908ULL;

} // namespace

TEST(SipHash24Tests, reference_vectors) {
  unsigned char input[64];
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

TEST(SipHash24Tests, digest_is_repeatable) {
  unsigned char input[30];
  for (size_t i = 0; i < sizeof(input); ++i) {
    input[i] = static_cast<unsigned char>(i);
  }

  SipHash24 hash(kKey0, kKey1);
  hash.update(input, sizeof(input));
  uint64_t digest = hash.digest();
  EXPECT_EQ(hash.digest(), digest);
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
  uint64_t split_digest = split.digest();
  EXPECT_EQ(split_digest, 0xd0f2cbb02e3b67c7ULL);

  SipHash24 whole(kKey0, kKey1);
  whole.update(input, 21);
  EXPECT_EQ(whole.digest(), split_digest);
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
