/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/asio.hpp>

#if !defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
#error Boost error: Local sockets not available
#endif

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/tables/applications/posix/docker_api.h>

namespace local = boost::asio::local;

namespace osquery {
namespace tables {

/**
 * @brief Docker UNIX domain socket path.
 *
 * By default docker creates UNIX domain socket at /var/run/docker.sock. If
 * docker domain is configured to use a different path specify that path.
 */
FLAG(string,
     docker_socket,
     "/var/run/docker.sock",
     "Docker UNIX domain socket path");

Status dockerApi(const std::string& uri, pt::ptree& tree) {
  try {
    local::stream_protocol::endpoint ep(FLAGS_docker_socket);
    local::stream_protocol::iostream stream(ep);
    if (!stream) {
      return Status(
          1, "Error connecting to docker sock: " + stream.error().message());
    }

    // Since keep-alive connections are not used, use HTTP/1.0
    stream << "GET " << uri
           << " HTTP/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
           << std::flush;
    if (stream.eof()) {
      stream.close();
      return Status(1, "Empty docker API response for: " + uri);
    }

    // All status responses are expected to be 200
    std::string str;
    getline(stream, str);
    if (str != "HTTP/1.0 200 OK\r") {
      stream.close();
      return Status(1, "Invalid docker API response for " + uri + ": " + str);
    }

    // Skip empty line between header and body
    while (!stream.eof() && str != "\r") {
      getline(stream, str);
    }

    try {
      pt::read_json(stream, tree);
    } catch (const pt::ptree_error& e) {
      stream.close();
      return Status(
          1, "Error reading docker API response for " + uri + ": " + e.what());
    }

    stream.close();
  } catch (const std::exception& e) {
    return Status(1, std::string("Error calling docker API: ") + e.what());
  }

  return Status(0);
}

bool checkStringIsHash(const std::string& str) {
  if (str.length() > 64) {
    VLOG(1) << "Constraint value is too long. Ignoring: " << str;
    return false;
  }
  for (size_t i = 0; i < str.length(); i++) {
    if (!isxdigit(str.at(i))) {
      VLOG(1) << "Constraint value is not SHA-256 hash. Ignoring: " << str;
      return false;
    }
  }
  return true;
}
}
}
