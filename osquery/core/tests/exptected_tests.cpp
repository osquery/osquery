//
//  exptected_tests.cpp
//  gmock
//
//  Created by Max Kareta on 5/15/18.
//

#include <gtest/gtest.h>
#include <osquery/core/error.h>
#include <osquery/core/expected.h>

namespace osquery {

GTEST_TEST(ExpectedValueTest, initialization) {
  ExpectedValue<std::string> value = std::string("Test");
  if (!value) {
    GTEST_FAIL();
  }
  EXPECT_EQ(value.get(), "Test");

  ExpectedValue<std::string> error =
      std::shared_ptr<Error>(new Error("Test", 1));
  if (error) {
    GTEST_FAIL();
  }
  EXPECT_EQ(error.getError()->getErrorCode(), 1);
}

GTEST_TEST(ExpectedTest, initialization) {
  osquery::Expected<std::string> sharedPointer =
      std::shared_ptr<std::string>(new std::string("Test"));
  if (!sharedPointer) {
    GTEST_FAIL();
  }
  EXPECT_EQ(*sharedPointer, "Test");

  osquery::Expected<std::string> uniquePointer =
      std::unique_ptr<std::string>(new std::string("Test"));
  if (!uniquePointer) {
    GTEST_FAIL();
  }
  EXPECT_EQ(*uniquePointer, "Test");

  osquery::Expected<std::string*> sharedPointer2 =
      std::shared_ptr<std::string>(new std::string("Test"));

  if (!sharedPointer2) {
    GTEST_FAIL();
  }
  EXPECT_EQ(*sharedPointer2, "Test");

  osquery::Expected<std::string*> error =
      std::shared_ptr<Error>(new Error("Test", 1));
  if (error) {
    GTEST_FAIL();
  }
  EXPECT_EQ(error.getError()->getErrorCode(), 1);
}

} // namespace osquery
