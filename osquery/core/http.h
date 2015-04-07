/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <boost/property_tree/json_parser.hpp>

namespace osquery {

enum VERB { GET, POST };

class Filter {
 public:
  std::string contents;
  static size_t handle(char* data, size_t size, size_t nmemb, void* p);
  size_t handle_impl(char* data, size_t size, size_t nmemb);
};

class HTTPResponse {
 private:
  long return_code;
  std::string contents;

 public:
  long getReturnCode() const;
  std::string getRaw() const;
  int getJSON(boost::property_tree::ptree& tree) const;

  HTTPResponse(long code);
  HTTPResponse(long code, const std::string& contents);
};

HTTPResponse makeRequest(const std::string& url,
                         const std::map<std::string, std::string> params,
                         const VERB verb);
HTTPResponse makeRequest(const std::string& url);
std::string decodeError(const HTTPResponse& resp);
}