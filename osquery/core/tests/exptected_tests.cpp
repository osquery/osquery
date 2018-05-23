//
//  exptected_tests.cpp
//  gmock
//
//  Created by Max Kareta on 5/15/18.
//

#include <gtest/gtest.h>
#include <osquery/error.h>
#include <osquery/expected.h>

namespace osquery {

GTEST_TEST(ExpectedValueTest, initialization) {
  Expected<std::string> value = std::string("Test");
  if (!value) {
    GTEST_FAIL();
  }
  EXPECT_EQ(value.get(), "Test");

  Expected<std::string> error = std::make_shared<Error>("Test", 1);
  if (error) {
    GTEST_FAIL();
  }
  EXPECT_EQ(error.getError()->getErrorCode(), 1);
}

osquery::ExpectedUnique<std::string> testFunction() {
  return std::make_unique<std::string>("Test");
}

GTEST_TEST(ExpectedPointerTest, initialization) {
  osquery::Expected<std::shared_ptr<std::string>> sharedPointer =
      std::make_shared<std::string>("Test");
  if (!sharedPointer) {
    GTEST_FAIL();
  }
  EXPECT_EQ(**sharedPointer, "Test");

  osquery::ExpectedUnique<std::string> uniquePointer = testFunction();
  if (!uniquePointer) {
    GTEST_FAIL();
  }
  EXPECT_EQ(**uniquePointer, "Test");

  osquery::ExpectedShared<std::string> sharedPointer2 =
      std::make_shared<std::string>("Test");

  if (!sharedPointer2) {
    GTEST_FAIL();
  }
  EXPECT_EQ(**sharedPointer2, "Test");

  osquery::ExpectedShared<std::string> error =
      std::make_shared<Error>("Test", 1);
  if (error) {
    GTEST_FAIL();
  }
  EXPECT_EQ(error.getError()->getErrorCode(), 1);
}

} // namespace osquery
