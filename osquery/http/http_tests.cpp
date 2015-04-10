/**
Copyright (c) 2010 Daniel Schauenberg

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This licence only applies to the files that it appears in.

* @brief header for the restclient class
* @author Daniel Schauenberg <d@unwiredcouch.com>
*/

#include "http.h"
#include <gtest/gtest.h>
#include <string>

namespace osquery {
class HttpGetTest : public testing::Test {
 protected:
  std::string url;
  std::string ctype;
  std::string data;

  HttpGetTest() {}

  virtual ~HttpGetTest() {}

  virtual void SetUp() {
    url = "http://http-test-server.herokuapp.com/";
    ctype = "";
    data = "";
  }

  virtual void TearDown() {}
};

// Tests
TEST_F(HttpGetTest, TestRestClientGETBody) {
  RestClient::response res = RestClient::get(url);
  EXPECT_EQ("GET", res.body);
}
// check return code
TEST_F(HttpGetTest, TestRestClientGETCode) {
  RestClient::response res = RestClient::get(url);
  EXPECT_EQ(200, res.code);
}
// check for failure
TEST_F(HttpGetTest, TestRestClientFailureCode) {
  std::string u = "http://nonexistent";
  RestClient::response res = RestClient::get(u);
  EXPECT_EQ(-1, res.code);
}

TEST_F(HttpGetTest, TestRestClientGETHeaders) {
  RestClient::response res = RestClient::get(url);
  EXPECT_EQ("keep-alive", res.headers["Connection"]);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}