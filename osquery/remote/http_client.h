/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#ifndef OPENSSL_NO_SSL2
#define OPENSSL_NO_SSL2 1
#endif

#ifndef OPENSSL_NO_SSL3
#define OPENSSL_NO_SSL3 1
#endif

#define OPENSSL_NO_MD5 1
#define OPENSSL_NO_DEPRECATED 1

// TODO(5591) Remove this when addressed by Boost's ASIO config.
// https://www.boost.org/doc/libs/1_67_0/boost/asio/detail/config.hpp
// Standard library support for std::string_view.
#define BOOST_ASIO_DISABLE_STD_STRING_VIEW 1

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
// clang-format on

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/optional/optional.hpp>

#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <osquery/remote/uri.h>

#include <osquery/logger.h>

namespace boost_system = boost::system;
namespace boost_asio = boost::asio;
namespace beast_http = boost::beast::http;

namespace osquery {
namespace http {

typedef boost_asio::ssl::stream<boost_asio::ip::tcp::socket&> ssl_stream;
typedef beast_http::request<beast_http::string_body> beast_http_request;
typedef beast_http::response<beast_http::string_body> beast_http_response;
typedef beast_http::response_parser<beast_http::string_body>
    beast_http_response_parser;
typedef beast_http::request_serializer<beast_http::string_body>
    beast_http_request_serializer;

template <typename T>
class HTTP_Request;
template <typename T>
class HTTP_Response;
typedef HTTP_Request<beast_http_request> Request;
typedef HTTP_Response<beast_http_response> Response;

/**
 * @brief A simple HTTP client class based upon Boost.Beast.
 *        This General-purpose HTTP Client allows HTTP and HTTPS.
 *
 * Implements put, post, get, head and delete methods.
 * These methods take request as reference and  return response by value.
 *
 * This does not allow HTTP for the TLS logger plugins.
 * It uses a state variable `Options::ssl_connection_` to determine if the
 * connection
 * should be wrapped in a TLS socket.
 */
class Client {
 public:
  /**
   * @brief Client options class.
   *
   * Behavior of the Client class is driven by its options.
   * E.g. secured client or non-secured client.
   * Or if the client will talk to server via proxy.
   */
  class Options {
   public:
    Options()
        : ssl_options_(0),
          timeout_(0),
          always_verify_peer_(false),
          follow_redirects_(false),
          keep_alive_(false),
          ssl_connection_(false) {}

    Options& ssl_connection(bool ct) {
      ssl_connection_ = ct;
      return *this;
    }

    Options& keep_alive(bool ka) {
      keep_alive_ = ka;
      return *this;
    }

    Options& follow_redirects(bool fr) {
      follow_redirects_ = fr;
      return *this;
    }

    Options& always_verify_peer(bool avp) {
      always_verify_peer_ = avp;
      return *this;
    }

    Options& timeout(int to) {
      timeout_ = to;
      return *this;
    }

    Options& openssl_ciphers(std::string const& ciphers) {
      ciphers_ = ciphers;
      return *this;
    }

    Options& openssl_options(long so) {
      ssl_options_ = so;
      return *this;
    }

    Options& openssl_verify_path(std::string const& vp) {
      verify_path_ = vp;
      return *this;
    }

    Options& openssl_certificate(std::string const& scf) {
      server_certificate_ = scf;
      return *this;
    }

    Options& openssl_certificate_file(std::string const& ccf) {
      client_certificate_file_ = ccf;
      return *this;
    }

    Options& openssl_private_key_file(std::string const& cpkf) {
      client_private_key_file_ = cpkf;
      return *this;
    }

    Options& openssl_sni_hostname(std::string const& sni_h) {
      sni_hostname_ = sni_h;
      return *this;
    }

    Options& proxy_hostname(std::string const& prxy_h) {
      proxy_hostname_ = prxy_h;
      return *this;
    }

    Options& remote_hostname(std::string const& remote_h) {
      remote_hostname_ = remote_h;
      return *this;
    }

    Options& remote_port(std::string const& remote_p) {
      remote_port_ = remote_p;
      return *this;
    }

    bool operator==(Options const& ropts) {
      return (server_certificate_ == ropts.server_certificate_) &&
             (verify_path_ == ropts.verify_path_) &&
             (client_certificate_file_ == ropts.client_certificate_file_) &&
             (client_private_key_file_ == ropts.client_private_key_file_) &&
             (ciphers_ == ropts.ciphers_) &&
             (sni_hostname_ == ropts.sni_hostname_) &&
             (ssl_options_ == ropts.ssl_options_) &&
             (always_verify_peer_ == ropts.always_verify_peer_) &&
             (proxy_hostname_ == ropts.proxy_hostname_) &&
             (keep_alive_ == ropts.keep_alive_);
    }

   private:
    boost::optional<std::string> server_certificate_;
    boost::optional<std::string> verify_path_;
    boost::optional<std::string> client_certificate_file_;
    boost::optional<std::string> client_private_key_file_;
    boost::optional<std::string> ciphers_;
    boost::optional<std::string> sni_hostname_;
    boost::optional<std::string> proxy_hostname_;
    boost::optional<std::string> remote_hostname_;
    boost::optional<std::string> remote_port_;
    long ssl_options_;
    int timeout_;
    bool always_verify_peer_;
    bool follow_redirects_;
    bool keep_alive_;
    bool ssl_connection_;
    friend class Client;
  };

 public:
  Client(Options const& opts = Options())
      : client_options_(opts), r_(ios_), sock_(ios_), timer_(ios_) {
// Fix #4235, #5341: Boost on Windows requires notification that it should
// let windows manage thread cleanup. *Do not remove this on Windows*
#ifdef WIN32
    boost::asio::detail::win_thread::set_terminate_threads(true);
#endif
  }

  void setOptions(Options const& opts) {
    new_client_options_ = !(client_options_ == opts);
    if (new_client_options_) {
      client_options_ = opts;
    }
  }

  /// HTTP put request method.
  Response put(Request& req,
               std::string const& body,
               std::string const& content_type = std::string());

  /// HTTP put request method with rvalue reference to body param.
  Response put(Request& req,
               std::string&& body,
               std::string const& content_type = std::string());

  /// HTTP post request method.
  Response post(Request& req,
                std::string const& body,
                std::string const& content_type = std::string());

  /// HTTP post request method with rvalue reference to body param.
  Response post(Request& req,
                std::string&& body,
                std::string const& content_type = std::string());

  /// HTTP get request method.
  Response get(Request& req);

  /// HTTP head request method.
  Response head(Request& req);

  /// HTTP delete_ request method.
  Response delete_(Request& req);

  ~Client() {
    closeSocket();
  }

 private:
  /// Create Connection to server, if proxy option is set, connect to proxy.
  void createConnection();

  /// Convert plain socket to TLS socket.
  void encryptConnection();

  template <typename STREAM_TYPE>
  void sendRequest(STREAM_TYPE& stream,
                   Request& req,
                   beast_http_response_parser& resp);

  bool initHTTPRequest(Request& req);
  Response sendHTTPRequest(Request& req);

  /// Handles HTTP request timeout.
  void timeoutHandler(boost_system::error_code const& ec);

  /**
   * @brief Handles response if requests completes or aborted due to timeout.
   *
   * In the postResponseHandler, treating SHORT_READ_ERROR as success for TLS
   * connections. This can happen if a remote server did not call shutdown on
   * the TLS connection.
   */
  void postResponseHandler(boost_system::error_code const& ec);

  bool isSocketOpen() {
    return sock_.is_open();
  }

  void closeSocket();

 private:
  Options client_options_;
  boost_asio::io_service ios_;
  boost_asio::ip::tcp::resolver r_;
  boost_asio::ip::tcp::socket sock_;
  boost_asio::deadline_timer timer_;
  std::shared_ptr<ssl_stream> ssl_sock_;
  boost_system::error_code ec_;
  bool new_client_options_{true};
};

/**
 * @brief HTTP request class.
 *
 * This class is inherited from implementation(boost.beast) request class.
 * It extends the functionality via providing URI parsing.
 *
 */
template <typename T>
class HTTP_Request : public T {
 public:
  /**
   * @brief HTTP request header helper class.
   *
   * Constructor of this class takes (name, value) pair, which is used to set
   * the request header of a HTTP request with the help of overloaded
   * function 'operator<<' of HTTP_Request class.
   */
  struct Header {
    Header(const std::string& name, const std::string& value)
        : name_(name), value_(value) {}

   private:
    std::string name_;
    std::string value_;
    friend class HTTP_Request<T>;
  };

 public:
  HTTP_Request(const std::string& url = std::string())
      : uri_(osquery::Uri(url)) {}

  /// Returns the host part of a URI.
  boost::optional<std::string> remoteHost() {
    return (!uri_.host().empty()) ? uri_.host()
                                  : boost::optional<std::string>();
  }

  /// Returns the port part of a URI.
  boost::optional<std::string> remotePort() {
    return (uri_.port() > 0) ? std::to_string(uri_.port())
                             : boost::optional<std::string>();
  }

  /// Returns the path, query, and fragment parts of a URI.
  boost::optional<std::string> remotePath() {
    std::string path;
    if (!uri_.path().empty()) {
      path += uri_.path();
    }

    if (!uri_.query().empty()) {
      path += '?' + uri_.query();
    }

    if (!uri_.fragment().empty()) {
      path += '#' + uri_.fragment();
    }
    return (!path.empty()) ? path : boost::optional<std::string>();
  }

  /// Returns the protocol part of a URI. E.g. 'http' or 'https'
  boost::optional<std::string> protocol() {
    return uri_.scheme().size() ? uri_.scheme()
                                : boost::optional<std::string>();
  }

  /// overloaded operator to set header of a HTTP request
  HTTP_Request& operator<<(const Header& h) {
    this->T::set(h.name_, h.value_);
    return *this;
  }

  /// URI can also be set via this method, useful for redirected request.
  void uri(const std::string& url) {
    uri_ = osquery::Uri(url);
  }

 private:
  osquery::Uri uri_;
};

/**
 * @brief HTTP response class.
 *
 * This class is inherited from implementation(boost.beast) HTTP response class.
 * This class gives convenient access to some functionality of implementation
 * specific HTTP response class.
 *
 */
template <typename T>
class HTTP_Response : public T {
 public:
  HTTP_Response() = default;

  HTTP_Response(T&& resp) : T(std::move(resp)) {}

  template <typename ITER>
  class Iterator;
  class Headers;

  /// status of a HTTP response.
  unsigned status() {
    return this->T::result_int();
  }

  /// body of a HTTP response.
  const std::string& body() {
    return this->T::body();
  }

  /**
   * @brief All headers of a HTTP response.
   *
   * Headers can be accessed via HTTP_Response<T>::Iterator class.
   */
  Headers headers() {
    return Headers(this);
  }
};

/**
 * @brief HTTP response headers iterator class
 *
 */
template <typename T>
template <typename ITER>
class HTTP_Response<T>::Iterator {
 public:
  Iterator(ITER iter) : iter_(iter) {}

  Iterator operator++() {
    ++iter_;
    return *this;
  }

  Iterator operator++(int) {
    Iterator tmp = *this;
    ++*this;
    return tmp;
  }

  bool operator!=(const Iterator& it) const {
    return (iter_ != it.iter_);
  }

  auto operator-> () {
    return std::make_shared<std::pair<std::string, std::string>>(
        std::string(iter_->name_string()), std::string(iter_->value()));
  }

  auto operator*() {
    return std::make_pair(std::string(iter_->name_string()),
                          std::string(iter_->value()));
  }

 private:
  ITER iter_;
};

/**
 * @brief HTTP response headers helper class.
 *
 * This class gives convenient access to all the headers of the HTTP response.
 *
 * e.g. -
 * for (const auto& header : resp.headers()) {
 *   header.first;
 *   header.second;
 * }
 */
template <typename T>
class HTTP_Response<T>::Headers {
 public:
  Headers(T* resp) : resp_(resp) {}

  std::string operator[](const std::string& name) {
    return std::string(resp_->T::operator[](name));
  }

  auto begin() {
    return Iterator<decltype(resp_->T::begin())>(resp_->T::begin());
  }

  auto end() {
    return Iterator<decltype(resp_->T::end())>(resp_->T::end());
  }

 private:
  T* resp_;
};
}
}
