/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <libiptc/libiptc.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>

#include <osquery/tables/networking/linux/iptc_proxy.h>

struct iptcproxy_handle {
  struct iptc_handle* handle;

  struct iptcproxy_chain chain_data;

  struct iptcproxy_rule rule_data;
  const struct ipt_entry* prev_rule;
};

const iptcproxy_handle* iptcproxy_init(const char* filter)
{
  iptcproxy_handle* handle = calloc(1, sizeof(iptcproxy_handle));
  if (handle == NULL) {
    return NULL;
  }

  handle->handle = iptc_init(filter);
  if (handle->handle == NULL) {
    free((void*)handle);
    return NULL;
  }

  return handle;
}

void iptcproxy_free(const iptcproxy_handle* handle)
{
  if (handle == NULL) {
    return;
  }

  if (handle->handle != NULL) {
    iptc_free(handle->handle);
  }

  free((void*)handle);
}

static iptcproxy_chain* get_chain_data(
    const char* chain,
    struct iptcproxy_handle* handle)
{
  if (chain == NULL) {
    return NULL;
  }

  handle->chain_data.chain = chain;
  struct ipt_counters counters;
  handle->chain_data.policy = iptc_get_policy(chain, &counters, handle->handle);
  if (handle->chain_data.policy != NULL) {
    handle->chain_data.policy_data.pcnt = counters.pcnt;
    handle->chain_data.policy_data.bcnt = counters.bcnt;
  }

  return &(handle->chain_data);
}

const iptcproxy_chain* iptcproxy_first_chain(const iptcproxy_handle* handle)
{
  return get_chain_data(
      iptc_first_chain(handle->handle),
      (iptcproxy_handle*)handle);
}

const iptcproxy_chain* iptcproxy_next_chain(const iptcproxy_handle* handle)
{
  return get_chain_data(
      iptc_next_chain(handle->handle),
      (iptcproxy_handle*)handle);
}

static void parse_entry_match(
    const struct ipt_entry* rule,
    iptcproxy_handle* handle)
{
  // Get rule port details from the xt_entry_match object

  // m will never be NULL, elems is an array
  struct xt_entry_match* m = (struct xt_entry_match*)rule->elems;

  if (rule->ip.proto == IPPROTO_TCP) {
    // m_data will never be NULL if ip.proto is set to TCP/UDP
    struct ipt_tcp* m_data = (struct ipt_tcp*)m->data;

    handle->rule_data.match_data.valid = true;
    handle->rule_data.match_data.spts[0] = m_data->spts[0];
    handle->rule_data.match_data.spts[1] = m_data->spts[1];
    handle->rule_data.match_data.dpts[0] = m_data->dpts[0];
    handle->rule_data.match_data.dpts[1] = m_data->dpts[1];
  } else if (rule->ip.proto == IPPROTO_UDP) {
    struct ipt_udp* m_data = (struct ipt_udp*)m->data;

    handle->rule_data.match_data.valid = true;
    handle->rule_data.match_data.spts[0] = m_data->spts[0];
    handle->rule_data.match_data.spts[1] = m_data->spts[1];
    handle->rule_data.match_data.dpts[0] = m_data->dpts[0];
    handle->rule_data.match_data.dpts[1] = m_data->dpts[1];
  } else {
    handle->rule_data.match_data.valid = false;
  }
}

static void parse_ip_entry(
    const struct ipt_entry* rule,
    iptcproxy_handle* handle)
{
  const struct ipt_ip *ip = &(rule->ip);

  memcpy(
      &(handle->rule_data.ip_data.src),
      &(ip->src),
      sizeof(struct in_addr));
  memcpy(
      &(handle->rule_data.ip_data.dst),
      &(ip->dst),
      sizeof(struct in_addr));
  memcpy(
      &(handle->rule_data.ip_data.smsk),
      &(ip->smsk),
      sizeof(struct in_addr));
  memcpy(
      &(handle->rule_data.ip_data.dmsk),
      &(ip->dmsk),
      sizeof(struct in_addr));
  memcpy(
      &(handle->rule_data.ip_data.iniface),
      &(ip->iniface),
      IFNAMSIZ);
  memcpy(
      &(handle->rule_data.ip_data.outiface),
      &(ip->outiface),
      IFNAMSIZ);
  memcpy(
      &(handle->rule_data.ip_data.iniface_mask),
      &(ip->iniface_mask),
      IFNAMSIZ);
  memcpy(
      &(handle->rule_data.ip_data.outiface_mask),
      &(ip->outiface_mask),
      IFNAMSIZ);

  handle->rule_data.ip_data.proto = ip->proto;
  handle->rule_data.ip_data.flags = ip->flags;
  handle->rule_data.ip_data.invflags = ip->invflags;

  handle->rule_data.ip_data.proto = ip->proto;
}

static iptcproxy_rule* get_rule_data(
    const struct ipt_entry* rule,
    struct iptcproxy_handle* handle)
{
  handle->prev_rule = rule;
  if (rule == NULL) {
    return NULL;
  }

  handle->rule_data.target = iptc_get_target(rule, handle->handle);
  if (rule->target_offset) {
    handle->rule_data.match = true;
    parse_entry_match(rule, handle);
  } else {
    handle->rule_data.match = false;
  }

  parse_ip_entry(rule, handle);

  return &(handle->rule_data);
}

const iptcproxy_rule* iptcproxy_first_rule(
    const char* chain,
    const iptcproxy_handle* handle)
{
  return get_rule_data(
      iptc_first_rule(chain, handle->handle),
      (iptcproxy_handle*) handle);
}

const iptcproxy_rule* iptcproxy_next_rule(
    const iptcproxy_handle* handle)
{
  return get_rule_data(
      iptc_next_rule(handle->prev_rule, handle->handle),
      (iptcproxy_handle*) handle);
}
