/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <string>

#include <windows.h>
#include <netlistmgr.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>


namespace osquery {
namespace tables {

QueryData genConnectivity(QueryContext& context) {
  QueryData results;
  Row r;

  INetworkListManager *mgr = nullptr;
  HRESULT res = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, IID_NetworkListManager, &mgr);

  if (res != S_OK) {
    TLOG << "Failed to instantiate INetworkListManager";
    return results;
  }

  NLM_CONNECTIVITY connectivity = 0;
  res = mgr->GetConnectivity(&connectivity);

  if (res != S_OK) {
    TLOG << "GetConnectivity() failed";
    return results;
  }

  r["disconnected"] = INTEGER(connectivity & NLM_CONNECTIVITY_DISCONNECTED);
  r["ipv4_no_traffic"] = INTEGER(connectivity & NLM_CONNECTIVITY_IPV4_NOTRAFFIC);
  r["ipv6_no_traffic"] = INTEGER(connectivity & NLM_CONNECTIVITY_IPV6_NOTRAFFIC);
  r["ipv4_subnet"] = INTEGER(connectivity & NLM_CONNECTIVITY_IPV4_SUBNET);
  r["ipv4_local_network"] = INTEGER(connectivity & NLM_CONNECTIVITY_IPV4_LOCAL_NETWORK);
  r["ipv4_internet"] = INTEGER(connectivity & NLM_CONNECTIVITY_IPV4_INTERNET);
  r["ipv6_subnet"] = INTEGER(connectivity & NLM_CONNECTIVITY_IPV6_SUBNET);
  r["ipv6_local_network"] = INTEGER(connectivity & NLM_CONNECTIVITY_IPV6_LOCAL_NETWORK);
  r["ipv6_internet"] = INTEGER(connectivity & NLM_CONNECTIVITY_IPV6_INTERNET);

  results.push_back(std::move(r));
}

} // namespace tables
} // namespace osquery
