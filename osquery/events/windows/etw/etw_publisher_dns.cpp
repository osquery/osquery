/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <ctime>

#include <osquery/events/windows/etw/etw_publisher_dns.h>

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/system/errno.h>
#include <osquery/utils/system/windows/etw_helpers.h>

#include <windns.h>

namespace osquery {

FLAG(bool,
     enable_dns_lookup_events,
     false,
     "Enables the dns_lookup_events publisher");

// ETW Event publisher registration into the Osquery pub-sub framework
REGISTER_ETW_PUBLISHER(EtwPublisherDNS, kEtwDNSPublisherName.c_str());

// Publisher constructor
EtwPublisherDNS::EtwPublisherDNS() : EtwPublisherBase(kEtwDNSPublisherName){};

Status EtwPublisherDNS::setUp() {
  if (!FLAGS_enable_dns_lookup_events) {
    return Status::failure(kEtwDNSPublisherName +
                           " publisher disabled via configuration.");
  }

  // Userspace ETW Provider configuration
  EtwProviderConfig dnsETWconfig;
  dnsETWconfig.setName("Microsoft-Windows-DNS-Client");
  dnsETWconfig.setPreProcessor(getPreProcessorCallback());
  dnsETWconfig.setPostProcessor(getPostProcessorCallback());
  dnsETWconfig.addEventTypeToHandle(EtwEventType::DnsRequest);
  dnsETWconfig.setTraceFlags(
      EVENT_ENABLE_PROPERTY_SID); // Required to get user SID in extended data

  // Adding the provider to the ETW Engine
  Status userProviderAddStatus = EtwEngine().addProvider(dnsETWconfig);
  if (!userProviderAddStatus.ok()) {
    return userProviderAddStatus;
  }

  return Status::success();
}

// Callback to perform pre-processing logic
void EtwPublisherDNS::providerPreProcessor(
    const EVENT_RECORD& rawEvent, const krabs::trace_context& traceCtx) {
  // Helper accessors for userspace events
  const EVENT_HEADER& eventHeader = rawEvent.EventHeader;

  // ETW Event ID 3008 contains the DNS Request status
  if (eventHeader.EventDescriptor.Id != 3008) {
    return;
  }

  // ETW event schema parsing
  krabs::schema schema(rawEvent, traceCtx.schema_locator);
  krabs::parser parser(schema);

  // Internal ETW Event allocation
  std::shared_ptr<EtwEventData> newEvent = std::make_shared<EtwEventData>();
  if (newEvent == nullptr) {
    return;
  }

  // Allocating DNS monitoring specific payload
  EtwDnsRequestDataRef dnsRequestData = std::make_shared<EtwDnsRequestData>();
  if (!dnsRequestData) {
    return;
  }

  // Populating DNS monitoring fields
  newEvent->Header.Type = EtwEventType::DnsRequest;
  newEvent->Payload = dnsRequestData;
  dnsRequestData->ProcessId = rawEvent.EventHeader.ProcessId;
  dnsRequestData->QueryName =
      wstringToString(parser.parse<std::wstring>(L"QueryName"));
  dnsRequestData->QueryType = parser.parse<uint32_t>(L"QueryType");
  dnsRequestData->QueryStatus = parser.parse<uint32_t>(L"QueryStatus");
  dnsRequestData->QueryResults =
      wstringToString(parser.parse<std::wstring>(L"QueryResults"));
  dnsRequestData->UserSid = sidStringFromEtwRecord(rawEvent);

  // Raw Header update
  newEvent->Header.RawHeader = rawEvent.EventHeader;

  // Dispatch the event
  EtwController::instance().dispatchETWEvents(std::move(newEvent));
}

std::string dnsQueryTypeToString(WORD queryType) {
  switch (queryType) {
  case DNS_TYPE_ZERO:
    return "ZERO";
  case DNS_TYPE_A:
    return "A";
  case DNS_TYPE_NS:
    return "NS";
  case DNS_TYPE_MD:
    return "MD";
  case DNS_TYPE_MF:
    return "MF";
  case DNS_TYPE_CNAME:
    return "CNAME";
  case DNS_TYPE_SOA:
    return "SOA";
  case DNS_TYPE_MB:
    return "MB";
  case DNS_TYPE_MG:
    return "MG";
  case DNS_TYPE_MR:
    return "MR";
  case DNS_TYPE_NULL:
    return "NULL";
  case DNS_TYPE_WKS:
    return "WKS";
  case DNS_TYPE_PTR:
    return "PTR";
  case DNS_TYPE_HINFO:
    return "HINFO";
  case DNS_TYPE_MINFO:
    return "MINFO";
  case DNS_TYPE_MX:
    return "MX";
  case DNS_TYPE_TEXT:
    return "TEXT";
  case DNS_TYPE_RP:
    return "RP";
  case DNS_TYPE_AFSDB:
    return "AFSDB";
  case DNS_TYPE_X25:
    return "X25";
  case DNS_TYPE_ISDN:
    return "ISDN";
  case DNS_TYPE_RT:
    return "RT";
  case DNS_TYPE_NSAP:
    return "NSAP";
  case DNS_TYPE_NSAPPTR:
    return "NSAPPTR";
  case DNS_TYPE_SIG:
    return "SIG";
  case DNS_TYPE_KEY:
    return "KEY";
  case DNS_TYPE_PX:
    return "PX";
  case DNS_TYPE_GPOS:
    return "GPOS";
  case DNS_TYPE_AAAA:
    return "AAAA";
  case DNS_TYPE_LOC:
    return "LOC";
  case DNS_TYPE_NXT:
    return "NXT";
  case DNS_TYPE_EID:
    return "EID";
  case DNS_TYPE_NIMLOC:
    return "NIMLOC";
  case DNS_TYPE_SRV:
    return "SRV";
  case DNS_TYPE_ATMA:
    return "ATMA";
  case DNS_TYPE_NAPTR:
    return "NAPTR";
  case DNS_TYPE_KX:
    return "KX";
  case DNS_TYPE_CERT:
    return "CERT";
  case DNS_TYPE_A6:
    return "A6";
  case DNS_TYPE_DNAME:
    return "DNAME";
  case DNS_TYPE_SINK:
    return "SINK";
  case DNS_TYPE_OPT:
    return "OPT";
  case DNS_TYPE_DS:
    return "DS";
  case DNS_TYPE_RRSIG:
    return "RRSIG";
  case DNS_TYPE_NSEC:
    return "NSEC";
  case DNS_TYPE_DNSKEY:
    return "DNSKEY";
  case DNS_TYPE_DHCID:
    return "DHCID";
  case DNS_TYPE_NSEC3:
    return "NSEC3";
  case DNS_TYPE_NSEC3PARAM:
    return "NSEC3PARAM";
  case DNS_TYPE_TLSA:
    return "TLSA";
  case DNS_TYPE_UINFO:
    return "UINFO";
  case DNS_TYPE_UID:
    return "UID";
  case DNS_TYPE_GID:
    return "GID";
  case DNS_TYPE_UNSPEC:
    return "UNSPEC";
  case DNS_TYPE_ADDRS:
    return "ADDRS";
  case DNS_TYPE_TKEY:
    return "TKEY";
  case DNS_TYPE_TSIG:
    return "TSIG";
  case DNS_TYPE_IXFR:
    return "IXFR";
  case DNS_TYPE_AXFR:
    return "AXFR";
  case DNS_TYPE_MAILB:
    return "MAILB";
  case DNS_TYPE_MAILA:
    return "MAILA";
  case DNS_TYPE_ALL:
    return "ALL";
  case DNS_TYPE_WINS:
    return "WINS";
  case DNS_TYPE_WINSR:
    return "WINSR";
  default:
    return "Unknown";
  }
}

// Callback to perform post-processing logic
void EtwPublisherDNS::providerPostProcessor(const EtwEventDataRef& eventData) {
  auto event_context = createEventContext();

  // Sanity check on event types that this callback will handle
  if (eventData->Header.Type != EtwEventType::DnsRequest) {
    return;
  }

  auto dnsRequestData = std::get<EtwDnsRequestDataRef>(eventData->Payload);
  if (dnsRequestData == nullptr) {
    return;
  }

  dnsRequestData->ProcessImagePath =
      processImagePathFromProcessId(dnsRequestData->ProcessId);
  updateHardVolumeWithLogicalDrive(dnsRequestData->ProcessImagePath);
  updateUserInfo(dnsRequestData->UserSid, dnsRequestData->UserName);
  dnsRequestData->QueryTypeString =
      dnsQueryTypeToString(dnsRequestData->QueryType);

  // Event dispatch
  event_context->data = std::move(eventData);
  fire(event_context);
}

} // namespace osquery
