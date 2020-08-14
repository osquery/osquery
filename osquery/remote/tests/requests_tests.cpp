/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/remote/requests.h>
#include <osquery/remote/serializers/json.h>
#include <osquery/remote/transports/tls.h>
#include <osquery/remote/uri.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {

class RequestsTests : public testing::Test {
 public:
  void SetUp() {}
};

class MockTransport : public Transport {
 public:
  Status sendRequest() override {
    response_status_ = Status(0, "OK");
    return response_status_;
  }

  Status sendRequest(const std::string& params, bool compress) override {
    response_params_.add("foo", "baz");
    response_status_ = Status(0, "OK");
    return response_status_;
  }
};

class MockSerializer : public Serializer {
 public:
  std::string getContentType() const {
    return "mock";
  }

  Status serialize(const JSON& params, std::string& serialized) {
    return Status::success();
  }

  Status deserialize(const std::string& serialized, JSON& params) {
    return Status::success();
  }
};

TEST_F(RequestsTests, test_url) {
  Uri test("https://facebook.com");
  EXPECT_EQ("https", test.scheme());
  EXPECT_EQ("facebook.com", test.host());

  test = Uri("ftp://teddy@facebook.com:21");
  EXPECT_EQ("teddy", test.username());
  uint16_t port(21);
  EXPECT_EQ(port, test.port());

  test = Uri("https://osquery.io/schema?scroll=1&offset=2#table");
  EXPECT_EQ("/schema", test.path());
  EXPECT_EQ("table", test.fragment());
  EXPECT_EQ(2_sz, test.getQueryParams().size());

  test = Uri("https://[10:10:32::1:f]:8080");
  port = 8080;
  EXPECT_EQ(port, test.port());
  EXPECT_EQ("[10:10:32::1:f]", test.host());
}

TEST_F(RequestsTests, test_call) {
  Request<MockTransport, MockSerializer> req("foobar");
  auto s1 = req.call();
  EXPECT_TRUE(s1.ok());

  JSON params;
  auto s2 = req.getResponse(params);
  EXPECT_TRUE(s2.ok());
  JSON empty;
  EXPECT_EQ(params.doc(), empty.doc());
}

TEST_F(RequestsTests, test_call_with_params) {
  Request<MockTransport, MockSerializer> req("foobar");
  JSON params;
  params.add("foo", "bar");
  auto s1 = req.call(params);
  EXPECT_TRUE(s1.ok());

  JSON recv;
  auto s2 = req.getResponse(recv);
  EXPECT_TRUE(s2.ok());

  JSON expected;
  expected.add("foo", "baz");
  EXPECT_EQ(recv.doc(), expected.doc());
}

class CopyTransport : public Transport {
 public:
  Status sendRequest() override {
    response_status_ = Status(0, "OK");
    return response_status_;
  }

  Status sendRequest(const std::string& params, bool compress) override {
    // Optionally compress.
    response_status_ = Status(0, (compress) ? compressString(params) : params);
    return response_status_;
  }
};

class CopySerializer : public Serializer {
 public:
  std::string getContentType() const {
    return "copy";
  }

  Status serialize(const JSON& params, std::string& serialized) {
    auto it = params.doc().FindMember("copy");
    serialized = (it != params.doc().MemberEnd() && it->value.IsString()
                      ? it->value.GetString()
                      : "");

    return Status::success();
  }

  Status deserialize(const std::string& serialized, JSON& params) {
    return Status::success();
  }
};

TEST_F(RequestsTests, test_compression) {
  Request<CopyTransport, CopySerializer> req("foobar");

  // Ask the request to compress the output from serialization.
  req.setOption("compress", true);

  std::string uncompressed = "stringstringstringstring";
  for (size_t i = 0; i < 10; i++) {
    uncompressed += uncompressed;
  }

  // Our special 'copy' serializer copies input from the 'copy' key in params.
  JSON params;
  params.add("copy", uncompressed);

  // Similarly, the 'copy' transport copies the request params into the
  // response status.
  req.call(params);
  auto status = req.getResponse(params);

  auto compressed = status.getMessage();

  /*
   * gzip header has a field that specifies the OS the library was built on
   * we need to skip the 10th byte (index 9) while comparing compressed results
   *
   * Reference: http://www.zlib.org/rfc-gzip.html
   * https://github.com/madler/zlib/blob/master/zutil.h#L86
   */

  std::string expected1("\x1F\x8B\b\0\0\0\0\0\x2", 9);
  std::string expected2(
      "\xED\xC4\xB1\r\0\0\x4\0\xB0s\xC5"
      "b\xC0\xFFq\x84\xB5\x1D:"
      "\xDBY1\xB6m\xDB\xB6m\xDB\xB6m\xDB\xB6m\xDB\xB6m\xDB\xB6m\xDB\xB6m\xDB"
      "\xB6m\xDB\xB6m\xDB\xB6m\xDB\xB6m\xDB\xB6m\xFB\xF1\x1"
      "1j\xA0\xA8\0`\0\0",
      68);

  EXPECT_EQ(compressed.substr(0, 9), expected1);
  EXPECT_EQ(compressed.substr(10), expected2);
  EXPECT_LT(compressed.size(), uncompressed.size());
}
}
