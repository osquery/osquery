/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <mach-o/dyld.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>

#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>
#include <boost/make_unique.hpp>

#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void genSignatureForFile(const std::string& path, QueryData& results);

// Gets the full path to the current executable (only works on Darwin)
std::string getExecutablePath() {
  uint32_t size = 1024;

  while (true) {
    auto buf = boost::make_unique<char[]>(size);

    if (_NSGetExecutablePath(buf.get(), &size) == 0) {
      return std::string(buf.get());
    }

    // If we get here, the buffer wasn't large enough, and we need to
    // reallocate.  We just continue the loop and will reallocate above.
  }
}

// Get the full, real path to the current executable (only works on Darwin).
std::string getRealExecutablePath() {
  auto path = getExecutablePath();
  return fs::canonical(path).string();
}

class SignatureTest : public testing::Test {
 protected:
  void SetUp() { tempFile = kTestWorkingDirectory + "darwin-signature"; }

  void TearDown() {
    // End the event loops, and join on the threads.
    fs::remove_all(tempFile);
  }

 protected:
  std::string tempFile;
};

/*
 * Ensures that the signature for a signed binary is correct.
 *
 * We use `/bin/ls` as the test binary, since it should be present "everywhere".
 */
TEST_F(SignatureTest, test_get_valid_signature) {
  std::string path {"/bin/ls"};

  QueryData results;
  genSignatureForFile(path, results);

  Row expected = {
      {"path", path},
      {"signed", "1"},
      {"identifier", "com.apple.ls"},
      {"authority", "Software Signing"},
  };

  for (const auto& column : expected) {
    EXPECT_EQ(results.front()[column.first], column.second);
  }

  // Could check the team identifier but it is flaky on some distros.
  // ASSERT_TRUE(results.front()["team_identifier"].length() > 0);
  ASSERT_TRUE(results.front()["cdhash"].length() > 0);
}

/*
 * Ensures that the results for an unsigned binary are correct.
 *
 * We use the currently-running binary as the 'unsigned binary', rather than
 * relying on a particular binary to be present.
 */
TEST_F(SignatureTest, test_get_unsigned) {
  std::string path = getRealExecutablePath();

  QueryData results;
  genSignatureForFile(path, results);

  Row expected = {
      {"path", path}, {"signed", "0"},         {"identifier", ""},
      {"cdhash", ""}, {"team_identifier", ""}, {"authority", ""},
  };

  for (const auto& column : expected) {
    EXPECT_EQ(results.front()[column.first], column.second);
  }
}

/*
 * Ensures that the results for a signed but invalid binary are correct.
 *
 * This test is a bit of a hack - we copy an existing signed binary (/bin/ls,
 * like above), and then modify one byte in the middle of the file by XORing it
 * with 0xBA.  This should ensure that it differs from whatever the original
 * byte was, and should thus invalidate the signature.
 */
TEST_F(SignatureTest, test_get_invalid_signature) {
  std::string originalPath {"/bin/ls"};
  std::string newPath = tempFile;

  // Create a buffer to hold the entire file.
  std::vector<uint8_t> binary;
  binary.resize(fs::file_size(originalPath));
  ASSERT_TRUE(binary.size() > 0);

  // Open existing file
  FILE* f = fopen(originalPath.c_str(), "rb");
  ASSERT_TRUE(f != nullptr);

  // Read it to memory
  auto nread = fread(&binary[0], sizeof(uint8_t), binary.size(), f);
  fclose(f);
  ASSERT_EQ(nread, binary.size());

  // Actually modify a byte.
  size_t offset = binary.size() / 2;
  binary[offset] = binary[offset] ^ 0xBA;

  // Write it back to a file.
  f = fopen(newPath.c_str(), "wb");
  ASSERT_TRUE(f != nullptr);
  fwrite(&binary[0], sizeof(uint8_t), binary.size(), f);
  fclose(f);

  // Get the signature of this new file.
  QueryData results;
  genSignatureForFile(newPath, results);

  Row expected = {
      {"path", newPath},
      {"signed", "0"},
      {"identifier", "com.apple.ls"},
      {"authority", "Software Signing"},
  };

  for (const auto& column : expected) {
    EXPECT_EQ(results.front()[column.first], column.second);
  }
  ASSERT_TRUE(results.front().count("team_identifier") > 0);
  ASSERT_TRUE(results.front()["cdhash"].length() > 0);
}
}
}
