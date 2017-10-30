/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/logger.h>

#include "osquery/remote/http_client.h"

namespace osquery {
namespace http {

const std::string kHTTPSDefaultPort{"443"};
const std::string kHTTPDefaultPort{"80"};
const std::string kProxyDefaultPort{"3128"};

const long kSSLShortReadError{0x140000dbL};

/** This class is used to convert boost::system_exception
 *  to std::system_exception, since on freebsd osquery is on boost-1.64.
 *  Idea taken from boost-1.65
 */
class adapted_category : public std::error_category {
 public:
  explicit adapted_category(boost::system::error_category const* pc)
      : pc_(pc) {}

  const char* name() const noexcept {
    return pc_->name();
  }

  std::string message(int ev) const {
    return pc_->message(ev);
  }

 private:
  boost::system::error_category const* pc_;
};

void Client::postResponseHandler(boost_system::error_code const& ec) {
  if ((ec.category() == boost_asio::error::ssl_category) &&
      (ec.value() == kSSLShortReadError)) {
    // Ignoring short read error, set ec_ to success.
    ec_.clear();
  } else if ((ec.value() != boost_system::errc::operation_canceled) ||
             (ec.category() != boost_asio::error::system_category)) {
    ec_ = ec;
  }
}

void Client::closeSocket() {
  if (sock_.is_open()) {
    boost_system::error_code rc;
    sock_.shutdown(boost_asio::ip::tcp::socket::shutdown_both, rc);
    if (rc) {
      return;
    }
    sock_.close(rc);
  }
}

void Client::timeoutHandler(boost_system::error_code const& ec) {
  if (!ec) {
    closeSocket();
    ec_ = boost_system::errc::make_error_code(boost_system::errc::timed_out);
  }
}

void Client::createConnection() {
  if (!client_options_.remote_hostname_) {
    throw std::runtime_error("Remote hostname missing");
  }

  std::string port = (client_options_.proxy_hostname_)
                         ? kProxyDefaultPort
                         : *client_options_.remote_port_;

  std::string connect_host = (client_options_.proxy_hostname_)
                                 ? *client_options_.proxy_hostname_
                                 : *client_options_.remote_hostname_;

  std::size_t pos;
  if ((pos = connect_host.find(":")) != std::string::npos) {
    port = connect_host.substr(pos + 1);
    connect_host = connect_host.substr(0, pos);
  }

  closeSocket();
  boost_system::error_code rc;
  connect(sock_,
          r_.resolve(boost_asio::ip::tcp::resolver::query{connect_host, port}),
          rc);

  if (rc) {
    std::string error("Failed to connect to ");
    if (client_options_.proxy_hostname_) {
      error += "proxy host ";
    }
    error += connect_host + ":" + port;
    throw std::system_error(
        std::error_code(rc.value(), std::generic_category()), error);
  }

  if (client_options_.proxy_hostname_) {
    std::string remote_host = *client_options_.remote_hostname_;
    std::string remote_port = *client_options_.remote_port_;

    beast_http_request req;
    req.method(beast_http::verb::connect);
    req.target(remote_host + ":" + remote_port);
    req.version = 11;
    req.prepare_payload();
    beast_http::write(sock_, req);

    boost::beast::flat_buffer b;
    beast_http_response_parser rp;
    rp.skip(true);
    beast_http::read_header(sock_, b, rp);
    if (beast_http::to_status_class(rp.get().result()) !=
        beast_http::status_class::successful) {
      throw std::runtime_error(rp.get().reason().data());
    }
  }
}

void Client::encryptConnection() {
  boost_asio::ssl::context ctx{boost_asio::ssl::context::sslv23};

  if (client_options_.always_verify_peer_) {
    ctx.set_verify_mode(boost_asio::ssl::verify_peer);
  } else {
    ctx.set_verify_mode(boost_asio::ssl::verify_none);
  }

  if (client_options_.server_certificate_) {
    ctx.set_verify_mode(boost_asio::ssl::verify_peer);
    ctx.load_verify_file(*client_options_.server_certificate_);
  }

  if (client_options_.verify_path_) {
    ctx.set_verify_mode(boost_asio::ssl::verify_peer);
    ctx.add_verify_path(*client_options_.verify_path_);
  }

  if (client_options_.ciphers_) {
    ::SSL_CTX_set_cipher_list(ctx.native_handle(),
                              client_options_.ciphers_->c_str());
  }

  if (client_options_.ssl_options_) {
    ctx.set_options(client_options_.ssl_options_);
  }

  if (client_options_.client_certificate_file_) {
    ctx.use_certificate_file(*client_options_.client_certificate_file_,
                             boost_asio::ssl::context::pem);
  }

  if (client_options_.client_private_key_file_) {
    ctx.use_private_key_file(*client_options_.client_private_key_file_,
                             boost_asio::ssl::context::pem);
  }

  ssl_sock_ = std::make_shared<ssl_stream>(sock_, ctx);
  if (client_options_.sni_hostname_) {
    ::SSL_set_tlsext_host_name(ssl_sock_->native_handle(),
                               client_options_.sni_hostname_->c_str());
  }

  boost_system::error_code rc;
  ssl_sock_->handshake(boost_asio::ssl::stream_base::client, rc);

  if (rc) {
    throw std::system_error(rc.value(), adapted_category(&rc.category()));
  }
}

template <typename STREAM_TYPE>
void Client::sendRequest(STREAM_TYPE& stream,
                         Request& req,
                         beast_http_response_parser& resp) {
  req.target((req.remotePath()) ? *req.remotePath() : "/");
  req.version = 11;

  std::string host_header_value = *client_options_.remote_hostname_;
  if (ssl_connection && (kHTTPSDefaultPort != *client_options_.remote_port_)) {
    host_header_value += ":" + *client_options_.remote_port_;
  } else if (kHTTPDefaultPort != *client_options_.remote_port_) {
    host_header_value += ":" + *client_options_.remote_port_;
  }

  req.set(beast_http::field::host, host_header_value);
  req.prepare_payload();
  req.keep_alive(true);

  if (client_options_.timeout_) {
    timer_.async_wait(
        [=](boost_system::error_code const& ec) { timeoutHandler(ec); });
  }

  beast_http_request_serializer sr{req};
  beast_http::async_write(stream, sr, [&](boost_system::error_code const& ec) {
    if (client_options_.timeout_) {
      timer_.cancel();
    }

    if ((ec.value() != boost_system::errc::operation_canceled) ||
        (ec.category() != boost_asio::error::system_category)) {
      ec_ = ec;
    }
  });

  ios_.run();
  ios_.reset();

  if (ec_) {
    throw std::system_error(ec_.value(), adapted_category(&ec_.category()));
  }

  if (client_options_.timeout_) {
    timer_.async_wait(
        [=](boost_system::error_code const& ec) { timeoutHandler(ec); });
  }

  boost::beast::flat_buffer b;
  beast_http::async_read(
      stream, b, resp, [&](boost_system::error_code const& ec) {
        if (client_options_.timeout_) {
          timer_.cancel();
        }
        postResponseHandler(ec);
      });

  ios_.run();
  ios_.reset();

  if (ec_) {
    throw std::system_error(ec_.value(), adapted_category(&ec_.category()));
  }
}

Response Client::sendHTTPRequest(Request& req) {
  if (client_options_.timeout_) {
    timer_.expires_from_now(
        boost::posix_time::seconds(client_options_.timeout_));
  }

  do {
    if (req.remoteHost()) {
      client_options_.remote_hostname_ = *req.remoteHost();

      if (req.remotePort()) {
        client_options_.remote_port_ = *req.remotePort();
      } else if (req.protocol() && (*req.protocol()).compare("https") == 0) {
        client_options_.remote_port_ = kHTTPSDefaultPort;
      } else {
        client_options_.remote_port_ = kHTTPDefaultPort;
      }

      if (req.protocol()) {
        if ((*req.protocol()).compare("https") == 0) {
          ssl_connection = true;
        } else {
          ssl_connection = false;
        }
      }
    }

    beast_http_response_parser resp;
    createConnection();

    if (ssl_connection) {
      encryptConnection();
    }

    if (ssl_connection) {
      sendRequest(*ssl_sock_, req, resp);
    } else {
      sendRequest(sock_, req, resp);
    }

    switch (resp.get().result()) {
    case beast_http::status::moved_permanently:
    case beast_http::status::found:
    case beast_http::status::see_other:
    case beast_http::status::not_modified:
    case beast_http::status::use_proxy:
    case beast_http::status::temporary_redirect:
    case beast_http::status::permanent_redirect: {
      if (!client_options_.follow_redirects_) {
        return Response(resp.release());
      }

      std::string redir_url = Response(resp.release()).headers()["Location"];
      if (redir_url.empty()) {
        throw std::runtime_error(
            "Location header missing in redirect response.");
      }

      req.uri(redir_url);
      LOG(INFO) << "HTTP(S) request re-directed to: " << redir_url;
      break;
    }
    default:
      return Response(resp.release());
    }
  } while (true);
}

Response Client::put(Request& req,
                     std::string const& body,
                     std::string const& content_type) {
  req.method(beast_http::verb::put);
  req.body = body;
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::post(Request& req,
                      std::string const& body,
                      std::string const& content_type) {
  req.method(beast_http::verb::post);
  req.body = body;
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::put(Request& req,
                     std::string&& body,
                     std::string const& content_type) {
  req.method(beast_http::verb::put);
  req.body = std::move(body);
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::post(Request& req,
                      std::string&& body,
                      std::string const& content_type) {
  req.method(beast_http::verb::post);
  req.body = std::move(body);
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::get(Request& req) {
  req.method(beast_http::verb::get);
  return sendHTTPRequest(req);
}

Response Client::head(Request& req) {
  req.method(beast_http::verb::head);
  return sendHTTPRequest(req);
}

Response Client::delete_(Request& req) {
  req.method(beast_http::verb::delete_);
  return sendHTTPRequest(req);
}
}
}
