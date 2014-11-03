#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <exception>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>
#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/logger.h"

namespace osquery {
namespace tables {

// heavily influenced by github.com/kristrev/inet-diag-example
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING
};

#define TCPF_ALL 0xFFF
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

int send_diag_msg(int sockfd, int family) {
  struct msghdr msg;
  struct nlmsghdr nlh;
  struct inet_diag_req_v2 conn_req;
  struct sockaddr_nl sa;
  struct iovec iov[4];
  int retval = 0;

  memset(&msg, 0, sizeof(msg));
  memset(&sa, 0, sizeof(sa));
  memset(&nlh, 0, sizeof(nlh));
  memset(&conn_req, 0, sizeof(conn_req));

  sa.nl_family = AF_NETLINK;

  // IPv4 vs IPv6
  if (family == 1) {
    conn_req.sdiag_family = AF_INET;
  } else if (family == 2) {
    conn_req.sdiag_family = AF_INET6;
  }
  conn_req.sdiag_protocol = IPPROTO_TCP;

  conn_req.idiag_states = TCPF_ALL & ~((1 << TCP_SYN_RECV) |
                                       (1 << TCP_TIME_WAIT) | (1 << TCP_CLOSE));

  conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));

  nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
  nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

  nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  iov[0].iov_base = (void *)&nlh;
  iov[0].iov_len = sizeof(nlh);
  iov[1].iov_base = (void *)&conn_req;
  iov[1].iov_len = sizeof(conn_req);

  msg.msg_name = (void *)&sa;
  msg.msg_namelen = sizeof(sa);
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;

  retval = sendmsg(sockfd, &msg, 0);

  return retval;
}

Row parse_diag_msg(struct inet_diag_msg *diag_msg, int rtalen) {
  char local_addr_buf[INET6_ADDRSTRLEN];
  char remote_addr_buf[INET6_ADDRSTRLEN];

  memset(local_addr_buf, 0, sizeof(local_addr_buf));
  memset(remote_addr_buf, 0, sizeof(remote_addr_buf));

  // set up data structures depending on idiag_family type
  if (diag_msg->idiag_family == AF_INET) {
    inet_ntop(AF_INET,
              (struct in_addr *)&(diag_msg->id.idiag_src),
              local_addr_buf,
              INET_ADDRSTRLEN);
    inet_ntop(AF_INET,
              (struct in_addr *)&(diag_msg->id.idiag_dst),
              remote_addr_buf,
              INET_ADDRSTRLEN);
  } else if (diag_msg->idiag_family == AF_INET6) {
    inet_ntop(AF_INET6,
              (struct in_addr6 *)&(diag_msg->id.idiag_src),
              local_addr_buf,
              INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6,
              (struct in_addr6 *)&(diag_msg->id.idiag_dst),
              remote_addr_buf,
              INET6_ADDRSTRLEN);
  }

  // populate the Row from diag_msg fields
  Row row;
  row["inode"] = boost::lexical_cast<std::string>(diag_msg->idiag_inode);
  row["local_port"] =
      boost::lexical_cast<std::string>(ntohs(diag_msg->id.idiag_sport));
  row["remote_port"] =
      boost::lexical_cast<std::string>(ntohs(diag_msg->id.idiag_dport));
  row["local_ip"] = boost::lexical_cast<std::string>(local_addr_buf);
  row["remote_ip"] = boost::lexical_cast<std::string>(remote_addr_buf);
  return row;
}

void getPortInode(QueryData &results, int type) {
  int nl_sock = 0;
  int numbytes = 0;
  int rtalen = 0;
  struct nlmsghdr *nlh;
  uint8_t recv_buf[SOCKET_BUFFER_SIZE];
  struct inet_diag_msg *diag_msg;

  // set up the socket
  if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1) {
    close(nl_sock);
    return;
  }

  // send the inet_diag message
  if (send_diag_msg(nl_sock, type) < 0) {
    close(nl_sock);
    return;
  }

  // recieve netlink messages
  numbytes = recv(nl_sock, recv_buf, sizeof(recv_buf), 0);
  nlh = (struct nlmsghdr *)recv_buf;
  while (NLMSG_OK(nlh, numbytes)) {

    // close the socket once NLMSG_DONE header recieved
    if (nlh->nlmsg_type == NLMSG_DONE) {
      close(nl_sock);
      return;
    }

    if (nlh->nlmsg_type == NLMSG_ERROR) {
      close(nl_sock);
      return;
    }

    // parse and process netlink message
    diag_msg = (struct inet_diag_msg *)NLMSG_DATA(nlh);
    rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
    try {
      results.push_back(parse_diag_msg(diag_msg, rtalen));
    }
    catch (std::exception &e) {
      LOG(ERROR) << e.what();
    }

    nlh = NLMSG_NEXT(nlh, numbytes);
  }

  close(nl_sock);
  return;
}

QueryData genPortInode() {

  QueryData results;
  getPortInode(results, 1); // IPv4
  getPortInode(results, 2); // IPv6
  return results;
}
}
}
