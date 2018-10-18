#include <gtest/gtest.h>
#include "../pipe_liner.h"

class PipeLinerTest : public ::testing::Test {
protected:
  virtual void SetUp() {

  }
};

struct MyListener : public PipeLinerListener {
  virtual void onLine(std::string line) override {
    lines_.push_back(line);
  }
  std::vector<std::string> lines_;
};

const std::string TEST1 = "one\ntwo\nthree\n";
const std::string TEST2 = "abcdef0123456789";

TEST_F(PipeLinerTest, basic) {
  auto listener = MyListener();
  auto reader = PipeLiner(&listener);
  reader._onBuffer(TEST1.c_str(), TEST1.size());
  ASSERT_EQ(3, listener.lines_.size());
}

TEST_F(PipeLinerTest, no_line_ending) {
  auto listener = MyListener();
  auto reader = PipeLiner(&listener);
  reader._onBuffer(TEST1.c_str(), 2); // only present 2 chars of entire string
  ASSERT_EQ(0, listener.lines_.size());
}

TEST_F(PipeLinerTest, append) {
  auto listener = MyListener();
  auto reader = PipeLiner(&listener);
  reader._onBuffer(TEST1.c_str(), 2); // only present 2 chars of entire string
  reader._onBuffer(TEST1.c_str() + 2, TEST1.size()-2); // give rest of string
  ASSERT_EQ(3, listener.lines_.size());
}

TEST_F(PipeLinerTest, append_past_capacity) {
  auto listener = MyListener();
  auto reader = PipeLiner(&listener, (uint32_t)TEST2.size());

  reader._onBuffer(TEST2.c_str(), TEST2.size());
  ASSERT_EQ(0, listener.lines_.size());
  reader._onBuffer(TEST2.c_str(), TEST2.size());
  reader._onBuffer(TEST2.c_str(), TEST2.size());
  reader._onBuffer("\n", 1);
  ASSERT_EQ(1, listener.lines_.size());
  ASSERT_EQ(16+16+16, listener.lines_[0].size());
  auto tmp = TEST2 + TEST2 + TEST2;
  ASSERT_EQ(tmp, listener.lines_[0]);
}
