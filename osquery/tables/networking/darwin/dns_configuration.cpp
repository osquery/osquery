#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/networking/posix/utils.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

// A simple structure to hold DNS resolver information
struct DNSResolver {
  std::string index;
  std::string domain;
  std::string ifIndex;
  std::string flags;
  std::string reach;
  std::string order;
  std::string timeout;
  std::vector<std::string> nameservers;
  std::vector<std::string> searchDomains;
};

// Function to execute a command and return its output
std::string execCommand(const char* cmd) {
  char buffer[128];
  std::string result = "";
  FILE* pipe = popen(cmd, "r");
  if (!pipe)
    throw std::runtime_error("popen() failed!");
  try {
    while (fgets(buffer, sizeof buffer, pipe) != NULL) {
      result += buffer;
    }
  } catch (...) {
    pclose(pipe);
    throw;
  }
  pclose(pipe);
  return result;
}

bool containsValue(const std::string& key, const std::string& keyValue) {
  return key.find(keyValue) != std::string::npos;
}

// Function to parse the output of `scutil --dns`
std::vector<DNSResolver> parseDNSOutput(const std::string& output) {
  std::vector<DNSResolver> resolvers;
  std::istringstream stream(output);
  std::string line;
  DNSResolver currentResolver;

  while (getline(stream, line)) {
    if (containsValue(line, "resolver")) {
      if (!currentResolver.index.empty()) {
        resolvers.push_back(currentResolver);
        currentResolver = DNSResolver();
      }
      size_t pos = line.find_first_of("#");
      if (pos != std::string::npos) {
        currentResolver.index = line.substr(pos + 1);
      }
      continue;
    }

    size_t pos = line.find_first_of(":");
    if (pos != std::string::npos) {
      std::string key = line.substr(0, pos);
      std::string value = line.substr(pos + 2);

      if (containsValue(key, "nameserver")) {
        currentResolver.nameservers.push_back(value);
      } else if (containsValue(key, "search domain")) {
        currentResolver.searchDomains.push_back(value);
      } else if (containsValue(key, "domain")) {
        currentResolver.domain = value;
      } else if (containsValue(key, "if_index")) {
        currentResolver.ifIndex = value.substr(0, value.find_last_of("(") - 1);
      } else if (containsValue(key, "flags")) {
        currentResolver.flags = value;
      } else if (containsValue(key, "reach")) {
        currentResolver.reach = value;
      } else if (containsValue(key, "order")) {
        currentResolver.order = value;
      } else if (containsValue(key, "timeout")) {
        currentResolver.timeout = value;
      }
    }
  }
  if (!currentResolver.index.empty()) {
    resolvers.push_back(currentResolver);
  }

  return resolvers;
}

QueryData genDNSConfiguration(QueryContext& context) {
  QueryData results;

  try {
    std::string output = execCommand("scutil --dns");
    std::vector<DNSResolver> resolvers = parseDNSOutput(output);

    for (const auto& resolver : resolvers) {
      Row r;
      r["resolver_index"] = INTEGER(resolver.index);
      r["interface_index"] = INTEGER(resolver.ifIndex);
      r["flags"] = resolver.flags;
      r["reach"] = resolver.reach;
      r["order"] = INTEGER(resolver.order);
      r["timeout"] = resolver.timeout;
      r["nameservers"] = osquery::join(resolver.nameservers, ", ");
      r["search_domains"] = osquery::join(resolver.searchDomains, ", ");
      results.push_back(r);
    }

    return results;
  } catch (const std::exception& e) {
    LOG(ERROR) << "Failed running scutil --dns";
    LOG(ERROR) << e.what();
    return {};
  }

  return {};
}

} // namespace tables
} // namespace osquery