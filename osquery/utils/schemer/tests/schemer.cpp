/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/schemer/schemer.h>

#include <osquery/utils/conversions/to.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace osquery {
namespace {

class SchemerTests : public testing::Test {};

class TestArchiveReader {
 private:
  template <typename ValueType>
  ValueType getValue() const;

 public:
  template <typename KeyType, typename ValueType>
  void record(KeyType const& key, ValueType& value) {
    if (key == "Alpha") {
      value = getValue<ValueType>();
    } else if (key == "Bravo") {
      value = getValue<ValueType>();
    } else if (key == "Charlie") {
      value = getValue<ValueType>() + getValue<ValueType>();
    }
  }
};

template <>
int TestArchiveReader::getValue<int>() const {
  return 1234;
}

template <>
std::string TestArchiveReader::getValue<std::string>() const {
  return "water under the bridge";
}

class TestArchiveWriter {
 public:
  template <typename KeyType, typename ValueType>
  void record(KeyType const& key, ValueType& value) {
    auto ostr = std::ostringstream{};
    ostr << key << ':' << value << ' ';
    text += ostr.str();
  }

 public:
  std::string text;
};

class Alpha {
 public:
  template <typename Archive, typename ValueType>
  static void discloseSchema(Archive& a, ValueType& value) {
    schemer::record(a, "Alpha", value.alpha_);
    schemer::record(a, "Bravo", value.bravo_);
    schemer::record(a, "Charlie", value.charlie_);
  }

  auto const& getAlpha() const {
    return alpha_;
  }

  auto const& getBravo() const {
    return bravo_;
  }

  auto const& getCharlie() const {
    return charlie_;
  }

 private:
  // let's declare everything as private to make sure that even private members
  // can be serialized and deserialized by schemers
  int alpha_ = 712;
  std::string bravo_ = "Richard";
  int charlie_ = 413;
};

TEST_F(SchemerTests, serializing) {
  auto const alpha = Alpha{};
  auto writer = TestArchiveWriter{};
  Alpha::discloseSchema(writer, alpha);
  ASSERT_EQ(writer.text, "Alpha:712 Bravo:Richard Charlie:413 ");
}

TEST_F(SchemerTests, deserializing) {
  auto alpha = Alpha{};
  auto reader = TestArchiveReader{};
  Alpha::discloseSchema(reader, alpha);
  EXPECT_EQ(alpha.getAlpha(), 1234);
  EXPECT_EQ(alpha.getBravo(), "water under the bridge");
  EXPECT_EQ(alpha.getCharlie(), 1234 + 1234);
}

} // namespace
} // namespace osquery
