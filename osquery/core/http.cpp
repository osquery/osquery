/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/logger.h>
#include "osquery/core/http.h"

#include <curl/curl.h>

namespace pt = boost::property_tree;

namespace osquery {

std::string decodeError(const HTTPResponse& resp) {
  long code = resp.getReturnCode();
  switch (code) {
  case -1:
    return "cURL could not initalize.";
  case -2:
    return "Could not parse the JSON";
  case 200:
    return "Success";
  case 204:
    return "No conent";
  case 301:
    return "Moved permanently";
  case 304:
    return "Not modified";
  case 400:
    return "Bad request";
  case 401:
    return "Unauthorized";
  case 403:
    return "Forbidden";
  case 404:
    return "Page not found";
  case 405:
    return "Method not allowed";
  case 406:
    return "Unacceptable";
  case 411:
    return "Length required";
  default:
    return "Unknown code";
  }
}

HTTPResponse::HTTPResponse(long code) { return_code = code; }

HTTPResponse::HTTPResponse(long code, const std::string& contents) {
  return_code = code;
  this->contents = contents;
}

long HTTPResponse::getReturnCode() const { return return_code; }

std::string HTTPResponse::getRaw() const { return contents; }

int HTTPResponse::getJSON(pt::ptree& tree) const {
  try {
    pt::read_json(contents, tree);
  } catch (const pt::ptree_error& e) {
    VLOG(1)
        << "There was an error parsing the JSON read from a file: " << e.what();
    return -2;
  }
  return 0;
}

size_t Filter::handle(char* data, size_t size, size_t nmemb, void* p) {
  return static_cast<Filter*>(p)->handle_impl(data, size, nmemb);
}

size_t Filter::handle_impl(char* data, size_t size, size_t nmemb) {
  contents.append(data, size * nmemb);
  return size * nmemb;
}

std::string buildParams(const std::map<std::string, std::string> params) {
  std::string ret = "";
  if (params.size() == 0) {
    return "";
  }
  for (std::map<std::string, std::string>::const_iterator it = params.begin();
       it != params.end();
       it++) {
    ret += it->first;
    ret += "=";
    ret += it->second;
    ret += "&";
  }
  ret.pop_back();
  return ret;
}

HTTPResponse makeRequest(const std::string& url,
                         const std::map<std::string, std::string> params,
                         const VERB verb) {
  CURL* curl = curl_easy_init();
  if (curl == NULL) {
    return HTTPResponse(-1);
  }
  Filter f;

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  switch (verb) {
  case GET:
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    break;
  case POST:
  // Intentional fall through
  default:
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buildParams(params).c_str());
    break;
  }
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &Filter::handle);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &f);

  CURLcode res = curl_easy_perform(curl);
  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  curl_easy_cleanup(curl);

  return HTTPResponse(http_code, f.contents);
}

HTTPResponse makeRequest(const std::string& url) {
  std::map<std::string, std::string> m;
  return makeRequest(url, m, POST);
}
}