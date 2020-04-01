/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "http_event_publisher.h"
#include "httpparser/httprequestparser.h"
#include "httpparser/httpresponseparser.h"
#include "httpparser/request.h"
#include "httpparser/response.h"
#include "osquery/remote/serializers/json.h"
#include <arpa/inet.h>
#include <boost/range/adaptor/map.hpp>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/flags.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <set>
#include <sys/socket.h>
#include <vector>

namespace osquery {
#define IPV6_VERSION		0x60   
#define IPV4 IPVERSION
#define IPV6 (IPV6_VERSION >> 4)

typedef std::pair<std::string, std::string> LocalRemoteAddrs;
    
static const size_t kIPv6Length = sizeof(struct ip6_hdr);
    
/// Maximum bytes per packet.
static const int kSnapLength = 1518;

/// Avoid running pcap in a busy loop.
static const int kPacketBufferTimeoutMs = 1000;

/// Internal traffic filter
const std::string kInternalTrafficFilter =
    "not (src net (10 or 172.16/12 or 192.168/16 or 100.64/10 "
    "or 127.0/8 or 169.254/16) "
    "and dst net (10 or 172.16/12 or 192.168/16 or 100.64/10 or "
    "127.0/8 or 169.254/16))";

/// Filter get, post, put, delete, option
const std::string kHttpRequestFilter =
    "tcp[((tcp[12:1] & 0xf0) >> 2):4]= 0x47455420 or\
                                    tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354 or\
                                    tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50555420 or\
                                    tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x44454c45 or\
                                    tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50415443 or\
                                    tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48454144 or\
                                    tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x4f505449 or ";

const std::string kTLSTrafficFilter =
    "(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1 or "
    "tcp[tcp[12]/16*4+5]=2))";

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#pragma pack(push, 1)
/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type; /* IP? ARP? RARP? etc */
    };
    
    /* IP header */
    struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
 #define IP_RF 0x8000            /* reserved fragment flag */
 #define IP_DF 0x4000            /* dont fragment flag */
 #define IP_MF 0x2000            /* more fragments flag */
 #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
    };
 #pragma pack(pop)
    
 #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
 #define IP_V(ip)                (((ip)->ip_vhl) >> 4)
    
    /* TCP header */
    typedef u_int tcp_seq;
 #pragma pack(push, 1)
    struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
 #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
 #define TH_FIN  0x01
 #define TH_SYN  0x02
 #define TH_RST  0x04
 #define TH_PUSH 0x08
 #define TH_ACK  0x10
 #define TH_URG  0x20
 #define TH_ECE  0x40
 #define TH_CWR  0x80
 #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
    };
 #pragma pack(pop)
    
 #define SSL_MIN_GOOD_VERSION    0x002
 #define SSL_MAX_GOOD_VERSION    0x304    // let's be optimistic here!
    
 #define TLS_HANDSHAKE           22
 #define TLS_CLIENT_HELLO        1
 #define TLS_SERVER_HELLO        2
    
 #define OFFSET_HELLO_VERSION    9
 #define OFFSET_SESSION_LENGTH   43
 #define OFFSET_CIPHER_LIST      44
  
 /* Grease bytes to ignore */
    std::set<std::string> greaseBytes = {"0A0A","1A1A","2A2A","3A3A","4A4A","5A5A","6A6A","7A7A",
                                         "8A8A","9A9A","AAAA","BABA","CACA","DADA","EAEA","FAFA"};
    /* Implementation of whitelisting  */
    /*
     * @brief whitelisting of headers - to be included in other_headers column
     *
     * By default no headers are inlcuded in headers list.
     * headers specify them via this flag as a comma separated list.
     */
 FLAG(string,
      include_http_headers,
      "",
      "Comma-separated list of headers to be included in http_events table");
 
 /* fingerprint struct */
 struct fingerprint {
      uint16_t  extensions_length;
      uint8_t   *extensions;
      uint16_t  curves_length;
      uint8_t   *curves;
      uint16_t  sig_alg_length;
      uint8_t   *sig_alg;
      uint16_t  ec_point_fmt_length;
      uint8_t   *ec_point_fmt;
 };
    
 const char* ssl_version(u_short version) {
     static char hex[7];
     switch (version) {
         case 0x002: return "SSLv2";
         case 0x300: return "SSLv3";
         case 0x301: return "TLSv1.0";
         case 0x302: return "TLSv1.1";
         case 0x303: return "TLSv1.2";
         case 0x304: return "TLSv1.3";
     }
     snprintf(hex, sizeof(hex), "0x%04hx", version);
     return hex;
 }
    

 REGISTER(HTTPLookupEventPublisher, "event_publisher", "http_lookups");
 
 FLAG(bool,
      enable_http_lookups,
      false,
      "Enable the HTTP capture event publisher");

 FLAG(string,
      disable_events_filters,
      "",
      "Comma-separated list of filters(e.g. "
      "'internal_traffic') to disable specific default http filter.");

 Status HTTPLookupEventPublisher::setUp() {
   if (!FLAGS_enable_http_lookups) {
     return Status(1, "HTTP lookups publisher disabled via configuration.");
   }

   // PCAP has no payload[offset] field, so we need to get the payload offset
   // from the TCP header (offset 12, upper 4 bits, number of 4-byte words):
   // TLS Handshake starts with a '22' byte, version, length,
   // and then '01'/'02' for client/server hello
   // TLS Handshake starts with a '22' byte, version, length,
   // and then '01'/'02' for client/server hello

   httpFilter_.clear();
   httpFilter_ = {{"http_request", kHttpRequestFilter + kTLSTrafficFilter},
                  {"internal_traffic", kInternalTrafficFilter}};
   return Status(0, "OK");
 }

 void HTTPLookupEventPublisher::getFilters(std::string& sFilters) {
   for (auto& filter_name : osquery::split(FLAGS_disable_events_filters, ",")) {
     // To enforce unification we lower case all filters for matching
     std::transform(filter_name.begin(),
                    filter_name.end(),
                    filter_name.begin(),
                    ::tolower);

     size_t pos = 0;
     while (pos < httpFilter_.size()) {
       if (httpFilter_.at(pos).first == filter_name) {
         httpFilter_.erase(httpFilter_.begin() + pos);
         VLOG(1) << "HTTP filter disabled via flag :" << filter_name;
         break;
       }
       pos++;
     }
   }
   // AND all the filters in the list.
   size_t pos = 0;
   while (pos < httpFilter_.size()) {
     sFilters += httpFilter_.at(pos).second;
     if (pos != httpFilter_.size() - 1) {
       sFilters += " and ";
     }
     pos++;
   }
 }

 Status HTTPLookupEventPublisher::run() {
     TLOG << "Starting HTTP lookups publisher";
     
     // Open "any" devices for capture. Do not use promisc mode
     char err[PCAP_ERRBUF_SIZE];
     std::string sFilters;
     getFilters(sFilters);

     handle_ = pcap_open_live(NULL, kSnapLength, 0, kPacketBufferTimeoutMs, err);
     if (handle_ == nullptr) {
         LOG(ERROR) << "Could not open pcap capture devices: " << err;
         return Status(1, "Could not open pcap capture devices.");
     }

     if (pcap_compile(
             handle_, &fp_, sFilters.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
       LOG(ERROR) << "Could not compile filter expression";
       return Status(1, "Could not compile filter expression.");
     }
     
     if (pcap_setfilter(handle_, &fp_) == -1) {
         LOG(ERROR) << "Could not install filter";
         return Status(1, "Could not install filter.");
     }
     
     int rc = pcap_loop(handle_, -1, processPacket, (unsigned char*)this);
     if (rc == -1) {
         LOG(ERROR) << "Error running pcap loop";
         return Status(1, "Error running pcap loop.");
     } else {
         LOG(INFO) << "Stopping pcap loop";
         return Status(2, "Stopping pcap loop.");
     }
 }
 
 void HTTPLookupEventPublisher::stop() {
     if (handle_ != nullptr) {
         TLOG << "Stopping HTTP publisher";
         
         pcap_breakloop(handle_);
         pcap_freecode(&fp_);
         pcap_close(handle_);
         handle_ = nullptr;
     }
 }
 
 static inline bool readIPv4SourceDest(const unsigned char* packet,
                                       const uint32_t caplen,
                                       size_t* offset,
                                       LocalRemoteAddrs& addrs) {
     const size_t ipv4_len =  (((struct ip *)packet)->ip_hl << 2);
     if (caplen < (*offset + ipv4_len)) {
         TLOG << "Invalid packet (IPv4 header). Packet length: " << caplen
         << ". Offset: " << *offset;
         return false;
     }
     
     const struct ip* ip = reinterpret_cast<const struct ip*>(packet + *offset);
     *offset += ipv4_len;
     
     char local[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];
     inet_ntop(AF_INET, &ip->ip_dst, local, INET_ADDRSTRLEN);
     inet_ntop(AF_INET, &ip->ip_src, remote, INET_ADDRSTRLEN);
     addrs.first = std::string(local);
     addrs.second = std::string(remote);
     
     return true;
 }

 static inline bool readIPv6SourceDest(const unsigned char* packet,
                                       const uint32_t caplen,
                                       size_t* offset,
                                       LocalRemoteAddrs& addrs) {
     if (caplen < (*offset + kIPv6Length)) {
         TLOG << "Invalid packet (IPv6 header). Packet length: " << caplen
         << ". Offset: " << *offset;
         return false;
     }
     
     const struct ip6_hdr* ip =
     reinterpret_cast<const struct ip6_hdr*>(packet + *offset);
     *offset += kIPv6Length;
     
     char local[INET6_ADDRSTRLEN], remote[INET6_ADDRSTRLEN];
     inet_ntop(AF_INET6, &ip->ip6_dst, local, INET6_ADDRSTRLEN);
     inet_ntop(AF_INET6, &ip->ip6_src, remote, INET6_ADDRSTRLEN);
     addrs.first = std::string(local);
     addrs.second = std::string(remote);
     
     return true;
 }

 
 void HTTPLookupEventPublisher::processPacket(unsigned char* args,
                                              const struct pcap_pkthdr* header,
                                              const unsigned char* packet) {
     uint16_t type;
     /* declare pointers to packet headers */
     const struct sniff_ip *ip;              /* The IP header */
     const struct sniff_tcp *tcp;            /* The TCP header */
     const u_char *payload;                  /* Packet payload */
     
     //HTTP header
     std::string method = "";
     std::string protocol = "";
     std::string host = "";
     std::uint64_t host_port = 0;
     std::string uri = "";
     std::string user_agent = "";
     std::string content_type = "";
     std::string ja3 = "";
     std::string ja3_fingerprint = "";
     std::string other_headers = "";
     
     char src_address_buffer[64];
     char dst_address_buffer[64];
     
     std::string ja3CalcString;
     
     long s_port = 0;
     long d_port = 0;
     
     long size_ip;
     long size_iptotal;
     long size_tcp;
     long size_payload;

     /*Linux consists of 16 more bytes of Linux cooked capture header,Skipping.*/
     packet = packet + 16;

     uint8_t ip_version = *(uint8_t*)packet >> 4;
     switch (ip_version) {
         case IPV4:
             type = ETHERTYPE_IP;
             break;
         case IPV6:
             type = ETHERTYPE_IPV6;
             break;
         default:
             TLOG << "Invalid packet. Unknown version: " << ip_version;
             return;
     }
     
     size_t offset = 0;
     LocalRemoteAddrs addrs;

     switch (type) {
         case ETHERTYPE_IP: 
             if (!readIPv4SourceDest(packet, header->caplen, &offset, addrs)) {
                  TLOG << "Could not retrieve IP address";
                 return;
             }
             break;
         case ETHERTYPE_IPV6:
             if (!readIPv6SourceDest(packet, header->caplen, &offset, addrs)) {
                 return;
             }
             break;
     } 
     
     /* define/compute ip header offset */
     ip = (struct sniff_ip*)(packet);
     size_ip = IP_HL(ip)*4;
     if (size_ip < 20) {
         TLOG << "Invalid IP header length bytes :" << size_ip;
         return;
     }
        
     /* determine protocol */
     if(ip->ip_p != IPPROTO_TCP) {
         return;
     }
     
     /*
      *  OK, this packet is TCP.
      */
     
     /* define/compute tcp header offset */
     tcp = (struct sniff_tcp*)(packet + size_ip);
     size_tcp = TH_OFF(tcp)*4;
     if (size_tcp < 20) {
         TLOG << "Invalid TCP header length:" << size_tcp<< " bytes";
         return;
     }
     
     //Grab source and destination port
     s_port = ntohs(tcp->th_sport);
     d_port = ntohs(tcp->th_dport);
     
     /* compute tcp payload (segment) size */
     size_iptotal = ntohs(ip->ip_len);
     if (size_iptotal == 0 || size_iptotal > header->caplen) {
         /* if TSO is used, ip_len is 0x0000 */
         /* only process up to caplen bytes. */
         size_iptotal = header->caplen;
     }
     size_payload = size_iptotal - (size_ip + size_tcp);
     
     /* define/compute tcp payload (segment) offset */
     payload = (u_char *)(packet + size_ip + size_tcp);
     
     if (payload[0] == TLS_HANDSHAKE) {
         
         if (size_payload < OFFSET_CIPHER_LIST + 3) { // at least one cipher + compression
          TLOG << "TLS handshake header too short:" << size_payload << " bytes";
             return;
         }
         
         u_short proto_version = payload[1]*256 + payload[2];
         u_short hello_version = payload[OFFSET_HELLO_VERSION]*256 + payload[OFFSET_HELLO_VERSION+1];
         
         if (proto_version < SSL_MIN_GOOD_VERSION || proto_version >= SSL_MAX_GOOD_VERSION ||
             hello_version < SSL_MIN_GOOD_VERSION || hello_version >= SSL_MAX_GOOD_VERSION) {
             TLOG << "Bad tls version(s) :"<< ssl_version(hello_version);
             return;
         }
         
         
         const u_char *packet_data = &payload[OFFSET_SESSION_LENGTH];
         if (size_payload < OFFSET_SESSION_LENGTH + packet_data[0] + 3) {
             TLOG <<"SessionID too long: "<< packet_data[0]<< " bytes";
             return;
         }
         
         packet_data+= 1 + packet_data[0];
         switch (payload[5]) {
             case TLS_CLIENT_HELLO: {
                 static struct fingerprint *fp_packet = nullptr;
                 if(fp_packet == nullptr) {
                     fp_packet = (fingerprint *)malloc(sizeof(struct fingerprint));
                     if(fp_packet == nullptr) {
                         TLOG << "Malloc Error (fp_packet)";
                         return;
                     }
                 }
                 
                 auto json = JSONSerializer();
                 JSON params;
                 char * server_name;
                 server_name = nullptr;
                 std::string cipherStr;
                 
                 u_short cs_len = packet_data[0]*256 + packet_data[1];
                 packet_data += 2; // skip cipher suites length
                 
                 // FIXME: check for buffer overruns
                 
                 for (int cs_id = 0; cs_id < cs_len/2; cs_id++) {
                     char buff[1000], decStr[1000];
                     buff[0] = '\0';
                     decStr[0] = '\0';
                     snprintf(buff, sizeof(buff), "%02hhX%02hhX", packet_data[2*cs_id], packet_data[2*cs_id + 1]);
                     if(greaseBytes.find(buff) != greaseBytes.end()) {
                         continue;
                     }
                     unsigned int x = std::stoul(buff, nullptr, 16);
                     snprintf(decStr, sizeof(decStr), "%d", x);
                     cipherStr+=decStr;
                     cipherStr+="-";
                 }
                 //Remove last "-"
                 cipherStr.pop_back();
                 
                 //compression method
                 size_t compression_pos = cs_len + 1;
                 size_t compression_len = packet_data[compression_pos];
                 compression_pos += 1+ compression_len;
                 
                /* Extensions */
                 size_t ext_len = ((size_t)packet_data[compression_pos] << 8) + (size_t)packet_data[compression_pos + 1];
                 size_t extensions_pos = compression_pos + 2;
                
                 /* Length */
                 packet_data += extensions_pos;
                 
                 /*
                  Set optional data to NULL in advance
                  */
                 fp_packet->curves = nullptr;
                 fp_packet->sig_alg = nullptr;
                 fp_packet->ec_point_fmt = nullptr;
                 server_name = nullptr;
                 /*
                  So this works - so overall length seems ok
                  */
                 uint8_t *extensions_tmp_ptr = (uint8_t *)packet_data;
                 
                 /*
                  If we are at the end of the packet we have no extensions, without this
                  we will just run off the end of the packet into unallocated space :/
                  */
                 if(packet_data - payload > size_payload) {
                     ext_len = 0;
                 }
                 /* Loop through the extensions */
                 size_t ext_id = 0;
                 int show_drops = 0, ext_count = 0;
                 /*
                  So this works - so overall length seems ok
                  */
                 fp_packet->extensions_length = 0;
                 for (ext_id = 0; ext_id < ext_len ; ext_id++ ) {
                     int ext_type;
                     
                     /* Set the extension type */
                     ext_type = (packet_data[ext_id]*256) + packet_data[ext_id + 1];
                     ext_count++;
                     
                     /* Handle some special cases */
                     switch(ext_type) {
                         case 0x000a:
                             /* elliptic_curves */
                             fp_packet->curves = (uint8_t *)&packet_data[ext_id + 2];
                             /* 2 & 3, not 0 & 1 because of 2nd length field */
                             fp_packet->curves_length = fp_packet->curves[2]*256 + fp_packet->curves[3];
                             break;
                         case 0x000b:
                             /* ec_point formats */
                             fp_packet->ec_point_fmt = (uint8_t *)&packet_data[ext_id + 2];
                             fp_packet->ec_point_fmt_length = fp_packet->ec_point_fmt[2];
                             //printf("ec point length: %i\n", fp_packet->ec_point_fmt_length);
                             break;
                         case 0x000d:
                             /* Signature algorithms */
                             fp_packet->sig_alg = (uint8_t *)&packet_data[ext_id + 2];
                             fp_packet->sig_alg_length = fp_packet->sig_alg[2]*256 + fp_packet->sig_alg[3];
                             break;
                         case 0x0000:
                             /* Definitely *NOT* signature-worthy
                              * but worth noting for debugging source
                              * of packets during signature creation.
                              */
                             /* Server Name */
                             server_name = (char *)&packet_data[ext_id+2];
                             break;
                     }
                     
                     //Measure the lenght of the extention with the extention count
                     fp_packet->extensions_length = (ext_count * 2);
                     ext_id += (packet_data[ext_id + 2]*256) + packet_data[ext_id + 3] + 3;
                     
                     
                     if((packet_data + ext_id) >= (payload + size_payload)) {
                         if(show_drops == 1) {
                             TLOG << "Extension offset beyond end of packet " <<src_address_buffer << "to" << ntohs(tcp->th_sport) \
                             << "destination address buffer :" << dst_address_buffer<<":" << ntohs(tcp->th_dport);
                         }
                         return;
                     }
                     
                 }
                 
                 uint16_t extensions_malloc = 0;
                 /*
                  Extensions use offsets, etc so we can alloc those now.  Others however will just have pointers
                  and we can malloc if it becomes a signature.  For this reason we have extensions_malloc to track
                  the current size for easy reuse instead of consantly malloc and free'ing the space.
                  */
                 
                 if(extensions_malloc == 0) {
                     fp_packet->extensions = (uint8_t *)malloc(fp_packet->extensions_length);
                     extensions_malloc = fp_packet->extensions_length;
                 } else{
                     if(fp_packet->extensions_length > extensions_malloc) {
                         fp_packet->extensions = (uint8_t *)realloc(fp_packet->extensions, fp_packet->extensions_length);
                         extensions_malloc = fp_packet->extensions_length;
                     }
                 }
                 if(fp_packet->extensions == nullptr) {
                     TLOG <<"Malloc Error (extensions)";
                     return;
                 }
                 
                 // Load up the extensions
                 int unarse = 0;
                 size_t arse;
                 for (arse = 0 ; arse < ext_len ;) {
                         fp_packet->extensions[unarse] = (uint8_t) extensions_tmp_ptr[arse];
                         fp_packet->extensions[unarse+1] = (uint8_t) extensions_tmp_ptr[arse+1];
                         unarse += 2;
                         arse = arse + 4 + (((uint8_t) extensions_tmp_ptr[(arse+2)])*256) + (uint8_t)(extensions_tmp_ptr[arse+3]);
                 }
                 
                 /*Construct the server name/ host */
                 if(server_name != nullptr) {
                     for (arse = 7 ; arse <= (size_t)(server_name[0]*256 + server_name[1]) + 1 ; arse++) {
                         if (server_name[arse] > 0x20 && server_name[arse] < 0x7b) {
                             if(server_name[arse] != '\0') {
                                 //printf( "%c", server_name[arse]);
                                 host += server_name[arse];
                                 size_t found = host.find_first_of(":");
                                 if (found != std::string::npos) {
                                   host = host.substr(0, found);
                                   auto host_exp = tryTo<std::uint64_t>(
                                       host.substr(found, host.length()));
                                   if (host_exp) {
                                     host_port = host_exp.get();
                                   }
                             }
                         }
                         }
                     }
                 } else {
                     TLOG << "Host name not present in the packet";
                 }
                 
                 std::string extensionsStr;
                 if(fp_packet->extensions != nullptr) {
                 /* extension */
                 for (arse = 0 ; arse < fp_packet->extensions_length ;) {
                     char buff[1000], decStr[1000];
                     buff[0] = '\0';
                     decStr[0] = '\0';
                     snprintf(buff, sizeof(buff), "%.02X%.02X",fp_packet->extensions[arse], fp_packet->extensions[arse+1]);
                     if(greaseBytes.find(buff) != greaseBytes.end()) {
                         arse = arse + 2;
                         continue;
                     }
                     
                     unsigned int x = std::stoul(buff, nullptr, 16);
                     snprintf(decStr, sizeof(decStr), "%d", x);
                     arse = arse + 2;
                     extensionsStr+=decStr;
                     extensionsStr+="-";
                 }
                 extensionsStr.pop_back();
                 }
                 
                 std::string curveStr;
                 if(fp_packet->curves != nullptr) {
                     for (arse = 4 ; arse < fp_packet->curves_length + 4 &&
                         fp_packet->curves_length + 4 > 0 ; arse = arse + 2) {
                         char buff[1000], decStr[1000];
                         buff[0] = '\0';
                         decStr[0] = '\0';
                     
                         snprintf(buff, sizeof(buff), "%.02X%.02X", fp_packet->curves[arse], fp_packet->curves[arse+1]);
                         if(greaseBytes.find(buff) != greaseBytes.end()) {
                             continue;
                         }
                         unsigned int x = std::stoul(buff, nullptr, 16);
                         snprintf(decStr, sizeof(decStr), "%d", x);
                         curveStr+=decStr;
                         curveStr+="-";
                     }
                     curveStr.pop_back();
                 }
                 
                 //Grab ec point format
                 std::string ecPointStr;
                 if(fp_packet->ec_point_fmt != nullptr) {
                     // Jumping to "3" to get past the second length parameter... errrr... why?
                     for (arse = 4 ; arse < fp_packet->ec_point_fmt_length + 4; arse++) {
                         
                         char buff[1000], decStr[1000];
                         buff[0] = '\0';
                         decStr[0] = '\0';
                         
                         snprintf(buff, sizeof(buff),"%.2X", fp_packet->ec_point_fmt[arse]);
                         if(greaseBytes.find(buff) != greaseBytes.end()) {
                             continue;
                         }
                         
                         unsigned int x = std::stoul(buff, nullptr, 16);
                         snprintf(decStr, sizeof(decStr), "%d", x);
                         ecPointStr+=decStr;
                         ecPointStr+="-";
                     }
                     ecPointStr.pop_back();
                 }
                 
                 
                 //Update data
                 protocol = ssl_version(hello_version);
                 char hello_ver[1000];
                 hello_ver[0] = '\0';
                 snprintf(hello_ver, sizeof(hello_ver), "%d", hello_version);
                 
                 //Construct JA3 string
                 ja3+=hello_ver;
                 ja3+="," + cipherStr + "," +extensionsStr + "," + curveStr + "," + ecPointStr;
                 
                 //Calculate JA3 fingerprint
                 ja3_fingerprint = hashFromBuffer(HASH_TYPE_MD5, (void *)ja3.c_str(), ja3.length());
                 
                 HTTPLookupEventPublisher* ref = (HTTPLookupEventPublisher*)args;
                 auto ec = ref->createEventContextFrom(header->ts.tv_sec,
                                                       method,
                                                       protocol,
                                                       addrs.second,
                                                       addrs.first,
                                                       s_port,
                                                       d_port,
                                                       host,
                                                       host_port,
                                                       uri,
                                                       content_type,
                                                       user_agent,
                                                       ja3,
                                                       ja3_fingerprint,
                                                       other_headers);
                 ref->fire(ec);
                 
                 //Clean up memory
                 if(fp_packet->extensions != nullptr) {
                     free(fp_packet->extensions);
                     fp_packet->extensions = nullptr;
                 }
                 
                 if(fp_packet != nullptr) {
                     free(fp_packet);
                     fp_packet = nullptr;
                 }
                 
                 break;
             }
         }
         return;
     } else {
             //Packet request header starts from here
             offset = size_ip + size_tcp;
             //Two conditions are "POST" and "GET", judge the success shows that the network frame contains a HTTP get or post link
             httpparser::Request request;
             httpparser::HttpRequestParser parser;
             const char * actualHttpPacket =  (const char *)(packet + offset);
             parser.parse(request, actualHttpPacket,actualHttpPacket + std::strlen(actualHttpPacket));
         
             HTTPLookupEventPublisher* ref = (HTTPLookupEventPublisher*)args;
             method = request.method;
             uri = request.uri;
         
             auto json = JSONSerializer();
             JSON params;
         
             std::vector<httpparser::Request::HeaderItem>::iterator iter;
             iter = request.headers.begin();
             while(iter != request.headers.end()) {
                 std::transform(iter->name.begin(), iter->name.end(), iter->name.begin(), ::tolower);
                 if (iter->name == "host") {
                   size_t found = iter->value.find_first_of(":");
                   if (found != std::string::npos) {
                     host = iter->value.substr(0, found);
                     auto host_exp = tryTo<std::uint64_t>(
                         iter->value.substr(found, iter->value.length()));
                     if (host_exp) {
                       host_port = host_exp.get();
                     }
                   } else {
                     host = iter->value;
                   }
                 } else if (iter->name == "user-agent") {
                     user_agent = iter->value;
                 } else if (iter->name == "content-type") {
                     content_type = iter->value;
                 } else {  
                     //By default only add headers name, no value 
                     params.add(iter->name, "");
                     for (auto& includeHeader : osquery::split(FLAGS_include_http_headers, ",")) {
                             // To enforce unification we lower case all headers for matching
                             std::transform(includeHeader.begin(), includeHeader.end(), includeHeader.begin(), ::tolower);
                             if(includeHeader == iter->name ) {
                                 //Only add headers which are in include list
                                 params.add(iter->name, iter->value);
                             }
                     }
                 }
                 iter++;
             }
         
             std::string serialized;
             json.serialize(params, serialized);
             other_headers = serialized;

             auto ec = ref->createEventContextFrom(header->ts.tv_sec,
                                                   method,
                                                   protocol,
                                                   addrs.second,
                                                   addrs.first,
                                                   s_port,
                                                   d_port,
                                                   host,
                                                   host_port,
                                                   uri,
                                                   content_type,
                                                   user_agent,
                                                   ja3,
                                                   ja3_fingerprint,
                                                   other_headers);
             ref->fire(ec);
             }
     return;
 }

 HTTPLookupEventContextRef HTTPLookupEventPublisher::createEventContextFrom(
     const uint32_t time,
     const std::string& method,
     const std::string& protocol,
     const std::string& local,
     const std::string& remote,
     long s_port,
     long d_port,
     const std::string& host,
     const std::uint64_t& host_port,
     const std::string& uri,
     const std::string& content_type,
     const std::string& user_agent,
     const std::string& ja3,
     const std::string& ja3_fingerprint,
     const std::string& other_headers) {
   auto ec = createEventContext();
   ec->time = time;
   ec->method = method;
   ec->protocol = protocol;
   ec->local = local;
   ec->remote = remote;
   ec->s_port = s_port;
   ec->d_port = d_port;
   if (host.empty() && !remote.empty()) {
     /* If host is empty, assign using available remote IP*/
     ec->host = remote;
   } else {
     ec->host = host;
   }
   ec->host_port = host_port;
   ec->uri = uri;
   ec->content_type = content_type;
   ec->user_agent = user_agent;
   ec->ja3 = ja3;
   ec->ja3_fingerprint = ja3_fingerprint;
   ec->other_headers = other_headers;

   return ec;
 }
} // namespace osquery
