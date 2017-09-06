/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/http_client.h>
#include <osquery/logger.h>

namespace osquery {
namespace http {

/// This class is used to convert boost::system_exception
/// to std::system_exception on freebsd since it is on boost-1.64.
/// Idea taken from boost-1.65
class adapted_category : public std::error_category {
 public:
  explicit adapted_category(boost::system::error_category const* pc)
      : pc_(pc) {}

  virtual const char* name() const noexcept {
    return pc_->name();
  }

  virtual std::string message(int ev) const {
    return pc_->message(ev);
  }

 private:
  boost::system::error_category const* pc_;
};

/// In the postResponseHandler, treating SHORT_READ_ERROR as success
/// for ssl connections. This can happen if a remote server did not
/// call on shutdown ssl connection.
void Client::postResponseHandler(boost_system::error_code const& ec) {
  if ((ec.category() == boost_asio::error::ssl_category) &&
      (ec.value() == SHORT_READ_ERROR)) {
    // ignoring short read error
    ec_ = boost_system::errc::make_error_code(boost_system::errc::success);
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
                         ? std::to_string(PROXY_DEFAUT_PORT)
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
    if (rp.get().result() != beast_http::status::ok) {
      throw std::runtime_error(rp.get().reason().data());
    }
  }
}

void Client::sendEncryptedRequest(Request& req,
                                  beast_http_response_parser& resp) {
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

  boost_asio::ssl::stream<boost_asio::ip::tcp::socket&> stream{sock_, ctx};

  if (client_options_.sni_hostname_) {
    ::SSL_set_tlsext_host_name(stream.native_handle(),
                               client_options_.sni_hostname_->c_str());
  }

  boost_system::error_code rc;
  stream.handshake(boost_asio::ssl::stream_base::client, rc);

  if (rc) {
    throw std::system_error(rc.value(), adapted_category(&rc.category()));
  }

  req.target((req.remotePath()) ? *req.remotePath() : "/");
  req.version = 11;
  req << Request::Header("Host", *client_options_.remote_hostname_);
  req.prepare_payload();

  req.keep_alive(true);
  beast_http_request_serializer sr{req};
  beast_http::write(stream, sr);

  boost_asio::deadline_timer timer{ios_};
  if (client_options_.timeout_) {
    timer.expires_from_now(
        boost::posix_time::seconds(client_options_.timeout_));
    timer.async_wait(
        [=](boost_system::error_code const& ec) { timeoutHandler(ec); });
  }

  boost::beast::flat_buffer b;
  beast_http::async_read(
      stream, b, resp, [&](boost_system::error_code const& ec) {
        if (client_options_.timeout_) {
          timer.cancel();
        }
        postResponseHandler(ec);
      });

  ios_.run();
  ios_.reset();

  if (ec_) {
    throw std::system_error(ec_.value(), adapted_category(&ec_.category()));
  }
}

void Client::sendRequest(Request& req, beast_http_response_parser& resp) {
  req.target((req.remotePath()) ? *req.remotePath() : "/");
  req.version = 11;
  req << Request::Header("Host", *client_options_.remote_hostname_);
  req.prepare_payload();

  req.keep_alive(true);
  beast_http_request_serializer sr{req};
  beast_http::write(sock_, sr);

  boost_asio::deadline_timer timer{ios_};
  if (client_options_.timeout_) {
    timer.expires_from_now(
        boost::posix_time::seconds(client_options_.timeout_));
    timer.async_wait(
        [=](boost_system::error_code const& ec) { timeoutHandler(ec); });
  }

  boost::beast::flat_buffer b;
  beast_http::async_read(
      sock_, b, resp, [&](boost_system::error_code const& ec) {
        if (client_options_.timeout_) {
          timer.cancel();
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
  do {
    if (req.remoteHost()) {
      client_options_.remote_hostname_ = *req.remoteHost();

      if (req.remotePort()) {
        client_options_.remote_port_ = *req.remotePort();
      } else if (req.protocol() && (*req.protocol()).compare("https") == 0) {
        client_options_.remote_port_ = std::to_string(HTTPS_DEFAULT_PORT);
      } else {
        client_options_.remote_port_ = std::to_string(HTTP_DEFAULT_PORT);
      }

      if (req.protocol()) {
        if ((*req.protocol()).compare("https") == 0) {
          ssl_connection = true;
        } else {
          ssl_connection = false;
        }
      } else {
        ssl_connection = false;
      }
    }

    beast_http_response_parser resp;
    createConnection();
    if (ssl_connection) {
      sendEncryptedRequest(req, resp);
    } else {
      sendRequest(req, resp);
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
      if (!redir_url.size()) {
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
  if (content_type.size()) {
    req << Request::Header("Content-Type", content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::post(Request& req,
                      std::string const& body,
                      std::string const& content_type) {
  req.method(beast_http::verb::post);
  req.body = body;
  if (content_type.size()) {
    req << Request::Header("Content-Type", content_type);
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
