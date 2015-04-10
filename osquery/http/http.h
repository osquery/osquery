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

#ifndef INCLUDE_RESTCLIENT_H_
#define INCLUDE_RESTCLIENT_H_

#include <curl/curl.h>
#include <string>
#include <map>
#include <cstdlib>
#include <algorithm>

namespace osquery {

class RestClient {
 public:
  /**
   * public data definitions
   */
  typedef std::map<std::string, std::string> headermap;

  /** response struct for queries */
  typedef struct {
    int code;
    std::string body;
    headermap headers;
  } response;
  /** struct used for uploading data */
  typedef struct {
    const char* data;
    size_t length;
  } upload_object;

  /** public methods */
  // Auth
  static void clearAuth();
  static void setAuth(const std::string& user, const std::string& password);
  // HTTP GET
  static response get(const std::string& url);
  // HTTP POST
  static response post(const std::string& url,
                       const std::string& ctype,
                       const std::string& data);
  // HTTP PUT
  static response put(const std::string& url,
                      const std::string& ctype,
                      const std::string& data);
  // HTTP DELETE
  static response del(const std::string& url);

 private:
  // writedata callback function
  static size_t write_callback(void* ptr,
                               size_t size,
                               size_t nmemb,
                               void* userdata);

  // header callback function
  static size_t header_callback(void* ptr,
                                size_t size,
                                size_t nmemb,
                                void* userdata);
  // read callback function
  static size_t read_callback(void* ptr,
                              size_t size,
                              size_t nmemb,
                              void* userdata);
  static const char* user_agent;
  static std::string user_pass;

  // trim from start
  static inline std::string& ltrim(std::string& s) {
    s.erase(s.begin(),
            std::find_if(s.begin(), s.end(),
                         std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
  }

  // trim from end
  static inline std::string& rtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(
                                                   std::isspace))).base(),
            s.end());
    return s;
  }

  // trim from both ends
  static inline std::string& trim(std::string& s) { return ltrim(rtrim(s)); }
};
}
#endif // INCLUDE_RESTCLIENT_H_