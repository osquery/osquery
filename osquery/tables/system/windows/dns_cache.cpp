/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

typedef struct _DNS_CACHE_ENTRY {
  struct _DNS_CACHE_ENTRY* pNext; // Pointer to next entry
  PWSTR pszName; // DNS Record Name
  unsigned short wType; // DNS Record Type
  unsigned short wDataLength; // Not referenced
  unsigned long dwFlags; // DNS Record Flags
} DNSCACHEENTRY, *PDNSCACHEENTRY;

typedef int(WINAPI* DNS_GET_CACHE_DATA_TABLE)(PDNSCACHEENTRY);

std::string dnsTypeToString(unsigned short wType) {
  switch (wType) {
  case 1:
    return "A";
  case 2:
    return "NS";
  case 5:
    return "CNAME";
  case 6:
    return "SOA";
  case 12:
    return "PTR";
  case 13:
    return "HINFO";
  case 15:
    return "MX";
  case 16:
    return "TXT";
  case 17:
    return "RP";
  case 18:
    return "AFSDB";
  case 24:
    return "SIG";
  case 25:
    return "KEY";
  case 28:
    return "AAAA";
  case 29:
    return "LOC";
  case 33:
    return "SRV";
  case 35:
    return "NAPTR";
  case 36:
    return "KX";
  case 37:
    return "CERT";
  case 39:
    return "DNAME";
  case 41:
    return "OPT";
  case 42:
    return "APL";
  case 43:
    return "DS";
  case 44:
    return "SSHFP";
  case 45:
    return "IPSECKEY";
  case 46:
    return "RRSIG";
  case 47:
    return "NSEC";
  case 48:
    return "DNSKEY";
  case 49:
    return "DHCID";
  case 50:
    return "NSEC3";
  case 51:
    return "NSEC3PARAM";
  case 52:
    return "TLSA";
  case 53:
    return "SMIMEA";
  case 55:
    return "HIP";
  case 59:
    return "CDS";
  case 60:
    return "CDNSKEY";
  case 61:
    return "OPENPGPKEY";
  case 62:
    return "CSYNC";
  case 63:
    return "ZONEMD";
  case 249:
    return "TKEY";
  case 250:
    return "TSIG";
  case 251:
    return "IXFR";
  case 252:
    return "AXFR";
  case 255:
    return "*";
  case 256:
    return "URI";
  case 257:
    return "CAA";
  case 32768:
    return "TA";
  case 32769:
    return "DLV";
  }

  std::stringstream ss;
  ss << wType;
  return ss.str();
}

QueryData genDnsCache(QueryContext& context) {
  QueryData results;

  PDNSCACHEENTRY pEntry = (PDNSCACHEENTRY)malloc(sizeof(DNSCACHEENTRY));
  HINSTANCE hLib =
      LoadLibraryExW(L"DNSAPI.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  DNS_GET_CACHE_DATA_TABLE DnsGetCacheDataTable =
      (DNS_GET_CACHE_DATA_TABLE)GetProcAddress(hLib, "DnsGetCacheDataTable");

  int stat = DnsGetCacheDataTable(pEntry);
  pEntry = pEntry->pNext;
  while (pEntry != nullptr) {
    Row r;

    r["name"] = wstringToString(pEntry->pszName);
    r["type"] = dnsTypeToString(pEntry->wType);
    r["flags"] = INTEGER(pEntry->dwFlags);

    results.push_back(r);
    pEntry = pEntry->pNext;
  }
  free(pEntry);

  return results;
}
} // namespace tables
} // namespace osquery
