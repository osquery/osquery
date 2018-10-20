/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>
#include <stdarg.h>
#include <sstream>

#include <libipset/types.h>
#include <libipset/session.h>
#include <libipset/data.h>

#include <boost/foreach.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

static std::stringstream ipsetsXmlStream;

static Status parseIpsets(QueryData &results)
{
  namespace xml = boost::property_tree;
  xml::ptree pt;
  try{
    read_xml(ipsetsXmlStream, pt);
  }
  catch (xml::xml_parser_error &e) {
    return Status(1, std::string("Failed to read ipsets xml ") + e.what());
  }
  catch (...) {
    return Status(1, "Failed to read ipsets xml (unknown error)");
  }

  BOOST_FOREACH(xml::ptree::value_type const& value, pt.get_child("ipsets")) 
  { 
    if(value.first == "ipset") {
      auto ipset = value.second;
      Row r;
      r["name"] = ipset.get<std::string>("<xmlattr>.name");
      r["type"] = ipset.get<std::string>("type");
      r["revision"] = INTEGER(ipset.get<int>("revision"));
      r["family"] = ipset.get<std::string>("header.family");
      r["hash_size"] = INTEGER(ipset.get<int>("header.hashsize"));
      r["max_element"] = INTEGER(ipset.get<int>("header.maxelem"));
      r["mem_size"] = INTEGER(ipset.get<int>("header.memsize"));
      r["references"] = INTEGER(ipset.get<int>("header.references"));
      r["num_entries"] = INTEGER(ipset.get<int>("header.numentries"));

      std::stringstream ss;
      BOOST_FOREACH(xml::ptree::value_type const& v, ipset.get_child("members")){
        if( v.first == "member" ) {
          ss << v.second.get<std::string>("elem") << " ";
        }
      }
      r["members"] = ss.str();
      results.push_back(r);
    }
  }
  return Status();
}

static int outputToIpsetsXmlStream(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);

  ipsetsXmlStream << va_arg(ap, char*);
    
  va_end(ap); 
  return 0;
}

static struct ipset_session *ipsetSessionInit()
{
  ipset_load_types();

  auto session = ipset_session_init(outputToIpsetsXmlStream);
  if (session) {        
    ipset_session_output(session, IPSET_LIST_XML);
  }

  return session;
}

void getIpsets(QueryData &results)
{
  auto session = ipsetSessionInit();

  if (!session) {
    VLOG(1) << "Cannot initialize ipset session";    
    return;
  }

  if (ipset_cmd(session, IPSET_CMD_LIST, 0)) {
    VLOG(1) << "Failed to list ipsets: " << ipset_session_error(session);
  }
  else{
    auto status = parseIpsets(results);
    if (!status.ok()){
      VLOG(1) << status.what();
    }
  }

  ipset_session_fini(session);
}

QueryData genIpsets(QueryContext& context) {
  QueryData results;

  getIpsets(results);

  return results;
}
} // namespace tables
} // namespace osquery
