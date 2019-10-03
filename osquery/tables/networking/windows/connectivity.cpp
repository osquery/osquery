/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <string>

#include <netlistmgr.h>
#include <windows.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genConnectivity(QueryContext& context) {
  QueryData results;

  INetworkListManager* mgr = nullptr;
  HRESULT res = CoCreateInstance(CLSID_NetworkListManager,
                                 NULL,
                                 CLSCTX_ALL,
                                 IID_INetworkListManager,
                                 reinterpret_cast<void**>(&mgr));

  if (res != S_OK) {
    TLOG << "Failed to instantiate INetworkListManager";
    return results;
  }

  NLM_CONNECTIVITY connectivity;
  res = mgr->GetConnectivity(&connectivity);

  if (res != S_OK) {
    TLOG << "GetConnectivity() failed";
    mgr->Release();
    return results;
  }

  Row r;
  r["disconnected"] =
      INTEGER(bool(connectivity & NLM_CONNECTIVITY_DISCONNECTED));
  r["ipv4_no_traffic"] =
      INTEGER(bool(connectivity & NLM_CONNECTIVITY_IPV4_NOTRAFFIC));
  r["ipv6_no_traffic"] =
      INTEGER(bool(connectivity & NLM_CONNECTIVITY_IPV6_NOTRAFFIC));
  r["ipv4_subnet"] = INTEGER(bool(connectivity & NLM_CONNECTIVITY_IPV4_SUBNET));
  r["ipv4_local_network"] =
      INTEGER(bool(connectivity & NLM_CONNECTIVITY_IPV4_LOCALNETWORK));
  r["ipv4_internet"] =
      INTEGER(bool(connectivity & NLM_CONNECTIVITY_IPV4_INTERNET));
  r["ipv6_subnet"] = INTEGER(bool(connectivity & NLM_CONNECTIVITY_IPV6_SUBNET));
  r["ipv6_local_network"] =
      INTEGER(bool(connectivity & NLM_CONNECTIVITY_IPV6_LOCALNETWORK));
  r["ipv6_internet"] =
      INTEGER(bool(connectivity & NLM_CONNECTIVITY_IPV6_INTERNET));

  mgr->Release();
  results.push_back(std::move(r));
  return results;
}

} // namespace tables
} // namespace osquery
