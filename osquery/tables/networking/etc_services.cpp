#include <vector>
#include <string>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

QueryData parseEtcServicesContent(const std::string& content) {
  QueryData results;

  for (const auto& line : split(content, "\n")) {
    // Empty line or comment.
    if (line.size() == 0 || boost::starts_with(line, "#")) {
      continue;
    }

    // [0]: name port/protocol [aliases]
    // [1]: [comment]
    auto service_info_comment = split(line, "#");
    if (service_info_comment.size() > 2) {
      continue;
    }

    // [0]: name
    // [1]: port/protocol
    // [2]: [aliases0]
    // [3]: [aliases1]
    // [n]: [aliasesn]
    auto service_info = split(service_info_comment[0]);
    if (service_info.size() < 2) {
      continue;
    }

    // [0]: port [1]: protocol
    auto service_port_protocol = split(service_info[1], "/");
    if (service_port_protocol.size() != 2) {
      continue;
    }

    auto service_name = service_info[0];
    auto service_port = boost::lexical_cast<std::string>(service_port_protocol[0]);
    auto service_protocol = service_port_protocol[1];

    // Removes the name and the port/protcol elements.
    service_info.erase(service_info.begin(), service_info.begin() + 2);
    auto service_aliases = boost::algorithm::join(service_info, " ");

    Row r;
    r["name"] = service_name;
    r["port"] = service_port;
    r["protocol"] = service_protocol;
    r["aliases"] = service_aliases;
    // If there is a comment for the service.
    if (service_info_comment.size() == 2) {
      r["comment"] = service_info_comment[1];
    }
    results.push_back(r);
  }
  return results;
}

QueryData genEtcServices() {
  std::string content;
  auto s = osquery::readFile("/etc/services", content);
  if (s.ok()) {
    return parseEtcServicesContent(content);
  } else {
    LOG(ERROR) << "Error reading /etc/services: " << s.toString();
    return {};
  }
}
}
}
