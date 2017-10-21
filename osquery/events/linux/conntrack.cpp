/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <fnmatch.h>
#include <linux/limits.h>
#include <poll.h>

#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/events/linux/conntrack.h"

namespace osquery {

/// The conntrack subsystem may have a performance impact on the system.
FLAG(bool,
     disable_conntrack,
     true,
     "Disable receiving events from the conntrack subsystem");

REGISTER(ConntrackEventPublisher, "event_publisher", "conntrack");

Status ConntrackEventPublisher::setUp() {
  if (FLAGS_disable_conntrack) {
    return Status(1, "Publisher disabled via configuration");
  }

  nl_ = std::shared_ptr<struct mnl_socket>(mnl_socket_open(NETLINK_NETFILTER),
                                           mnl_socket_close);
  if (nl_ == nullptr) {
    return Status(1, "Could not open conntrack subsystem");
  }

  // TODO: How to test if kernel modules have been loaded?

  // TODO: Filter on event types? Move to configure() and select based on
  // subscriber?
  if (mnl_socket_bind(nl_.get(),
                      NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE |
                          NF_NETLINK_CONNTRACK_DESTROY,
                      MNL_SOCKET_AUTOPID) < 0) {
    return Status(1, "Could not subscribe to updates from conntrack subsystem");
  }

  return Status(0, "OK");
}
/**
 * @brief Process the netlink message as conntrack message.
 *
 * @param nlh the message received from conntrack subsystem
 * @param data the ConntrackEventContext to return the parsed struct
 * @return netlink success code
 */
static int data_cb(const struct nlmsghdr* nlh, void* data) {
  ConntrackEventContext* ec = reinterpret_cast<ConntrackEventContext*>(data);
  struct nf_conntrack* ct = ec->event.get();
  enum nf_conntrack_msg_type type = NFCT_T_UNKNOWN;

  switch (nlh->nlmsg_type & 0xFF) {
  case IPCTNL_MSG_CT_NEW:
    if (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL))
      type = NFCT_T_NEW;
    else
      type = NFCT_T_UPDATE;
    break;
  case IPCTNL_MSG_CT_DELETE:
    type = NFCT_T_DESTROY;
    break;
  }
  ec->type = type;

  if (ct == NULL)
    return MNL_CB_OK;

  nfct_nlmsg_parse(nlh, ct);
  /**
  char buf[4096];
  nfct_snprintf(buf, sizeof(buf), ct,
                type, NFCT_O_DEFAULT, 0);
  printf("%s\n", buf);
  **/

  return MNL_CB_OK;
}

Status ConntrackEventPublisher::run() {
  // Receive from netlink socket
  char buf[MNL_SOCKET_BUFFER_SIZE];
  long int ret = mnl_socket_recvfrom(nl_.get(), buf, sizeof(buf));
  if (ret == -1) {
    return Status(1, "Could not receive from mnl_socket");
  }

  // Run parsing callback and fire event
  std::shared_ptr<struct nf_conntrack> ct(nfct_new(), nfct_destroy);
  auto ec = createEventContextFrom(ct);
  ret = mnl_cb_run(buf, ret, 0, 0, data_cb, ec.get());
  if (ret == -1) {
    return Status(1, "Could not parse conntrack message with mnl_cb");
  }
  fire(ec);

  return Status(0, "OK");
}

ConntrackEventContextRef ConntrackEventPublisher::createEventContextFrom(
    std::shared_ptr<struct nf_conntrack> event) const {
  auto ec = createEventContext();
  ec->event = event;

  return ec;
}
}
