/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <map>
#include <sstream>

#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

#include "osquery/events/freebsd/devd.h"

namespace osquery {

REGISTER(DevdEventPublisher, "event_publisher", "iokit");

namespace {

const char* kDevdSocket = "/var/run/devd.seqpacket.pipe";
const size_t kDevdRecvBuf = 8192;

/// Parse devd "key=value key2=value2" attribute strings (values may be
/// double-quoted).  Whitespace separates pairs; quoted strings preserve
/// internal whitespace.
std::map<std::string, std::string> parseAttrs(const std::string& s) {
  std::map<std::string, std::string> out;
  size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) {
      i++;
    }
    if (i >= s.size()) {
      break;
    }
    auto eq = s.find('=', i);
    if (eq == std::string::npos) {
      break;
    }
    std::string key = s.substr(i, eq - i);
    i = eq + 1;
    std::string val;
    if (i < s.size() && s[i] == '"') {
      i++;
      auto end = s.find('"', i);
      if (end == std::string::npos) {
        val = s.substr(i);
        i = s.size();
      } else {
        val = s.substr(i, end - i);
        i = end + 1;
      }
    } else {
      auto end = i;
      while (end < s.size() &&
             !std::isspace(static_cast<unsigned char>(s[end]))) {
        end++;
      }
      val = s.substr(i, end - i);
      i = end;
    }
    out[key] = val;
  }
  return out;
}

/// Extract vendor/model ids from a pnp-info-style string.
/// E.g. "vendor=0x1022 device=0x1480 ..."
void extractIds(const std::map<std::string, std::string>& attrs,
                std::string& vendor_id,
                std::string& model_id) {
  auto it = attrs.find("vendor");
  if (it != attrs.end()) {
    vendor_id = it->second;
  }
  it = attrs.find("device");
  if (it != attrs.end()) {
    model_id = it->second;
  }
  // USB-style fallbacks.
  if (vendor_id.empty()) {
    it = attrs.find("idVendor");
    if (it != attrs.end()) {
      vendor_id = it->second;
    }
  }
  if (model_id.empty()) {
    it = attrs.find("idProduct");
    if (it != attrs.end()) {
      model_id = it->second;
    }
  }
}

} // namespace

Status DevdEventPublisher::setUp() {
  WriteLock lock(sock_mutex_);

  int s = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (s < 0) {
    return Status::failure(std::string("devd: socket() failed: ") +
                           strerror(errno));
  }

  struct sockaddr_un sa;
  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, kDevdSocket, sizeof(sa.sun_path) - 1);

  if (::connect(s, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) {
    int e = errno;
    ::close(s);
    return Status::failure(std::string("devd: connect(") + kDevdSocket +
                           ") failed: " + strerror(e));
  }

  sock_ = s;
  return Status::success();
}

void DevdEventPublisher::tearDown() {
  WriteLock lock(sock_mutex_);
  int s = sock_.exchange(-1);
  if (s >= 0) {
    ::close(s);
  }
}

void DevdEventPublisher::handleLine(const std::string& line) {
  if (line.empty()) {
    return;
  }

  // devd notification leading character:
  //   '+'  : device arrival (attach)
  //   '-'  : device departure (detach)
  //   '?'  : nomatch / query response (ignored)
  //   '!'  : kernel notification (ignored for hardware_events)
  //   other: ignore
  char kind = line[0];
  if (kind != '+' && kind != '-') {
    return;
  }

  // Body format: "<devname> at <attrs> on <parent>"
  // Example: "+da0 at bus=0 hubaddr=2 port=0 ... on usbus0"
  std::string body = line.substr(1);

  // Split out device name (first whitespace-delimited token).
  size_t name_end = 0;
  while (name_end < body.size() &&
         !std::isspace(static_cast<unsigned char>(body[name_end]))) {
    name_end++;
  }
  if (name_end == 0) {
    return;
  }
  std::string devname = body.substr(0, name_end);

  // Remainder may contain "at <attrs> on <parent>".  Pull the parent first.
  std::string rest = body.substr(name_end);
  std::string parent;
  auto on_pos = rest.rfind(" on ");
  if (on_pos != std::string::npos) {
    parent = rest.substr(on_pos + 4);
    // Strip trailing whitespace/newlines.
    while (!parent.empty() &&
           std::isspace(static_cast<unsigned char>(parent.back()))) {
      parent.pop_back();
    }
    rest = rest.substr(0, on_pos);
  }

  // Drop the leading " at " if present, leaving just attribute string.
  auto at_pos = rest.find(" at ");
  std::string attrs_str;
  if (at_pos != std::string::npos) {
    attrs_str = rest.substr(at_pos + 4);
  } else {
    attrs_str = rest;
  }

  auto attrs = parseAttrs(attrs_str);

  auto ec = createEventContext();
  ec->action = (kind == '+') ? DevdEventContext::DEVICE_ATTACH
                             : DevdEventContext::DEVICE_DETACH;
  ec->path = "/dev/" + devname;
  ec->driver = devname;

  // Bus type from the parent device name (usbus*, pci*, etc.).
  if (parent.rfind("usbus", 0) == 0) {
    ec->type = "USB";
  } else if (parent.rfind("pci", 0) == 0) {
    ec->type = "PCI";
  } else {
    ec->type = parent;
  }

  extractIds(attrs, ec->vendor_id, ec->model_id);

  auto it = attrs.find("vendor");
  if (it != attrs.end()) {
    ec->vendor = it->second;
  }
  it = attrs.find("product");
  if (it != attrs.end()) {
    ec->model = it->second;
  }
  it = attrs.find("sernum");
  if (it != attrs.end()) {
    ec->serial = it->second;
  }
  it = attrs.find("release");
  if (it != attrs.end()) {
    ec->version = it->second;
  }

  fire(ec);
}

Status DevdEventPublisher::run() {
  int s = sock_.load();
  if (s < 0) {
    return Status::failure("devd: socket not open");
  }

  struct pollfd pfd;
  pfd.fd = s;
  pfd.events = POLLIN;

  while (!isEnding()) {
    int rc = ::poll(&pfd, 1, 1000);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Status::failure(std::string("devd: poll: ") + strerror(errno));
    }
    if (rc == 0) {
      continue;
    }
    if (!(pfd.revents & POLLIN)) {
      continue;
    }

    char buf[kDevdRecvBuf];
    ssize_t n = ::recv(s, buf, sizeof(buf) - 1, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Status::failure(std::string("devd: recv: ") + strerror(errno));
    }
    if (n == 0) {
      // Peer closed; devd is gone.
      return Status::failure("devd: socket closed");
    }
    buf[n] = '\0';

    // SOCK_SEQPACKET preserves message boundaries; each message is one
    // notification line.  But some FreeBSD versions deliver multi-line
    // packets, so split on '\n' defensively.
    std::string packet(buf, static_cast<size_t>(n));
    size_t start = 0;
    while (start < packet.size()) {
      auto nl = packet.find('\n', start);
      if (nl == std::string::npos) {
        handleLine(packet.substr(start));
        break;
      }
      handleLine(packet.substr(start, nl - start));
      start = nl + 1;
    }
  }

  return Status::success();
}

bool DevdEventPublisher::shouldFire(const DevdSubscriptionContextRef& sc,
                                    const DevdEventContextRef& ec) const {
  if (!sc->type.empty() && sc->type != ec->type) {
    return false;
  }
  if (!sc->vendor_id.empty() && sc->vendor_id != ec->vendor_id) {
    return false;
  }
  if (!sc->model_id.empty() && sc->model_id != ec->model_id) {
    return false;
  }
  return true;
}

} // namespace osquery
