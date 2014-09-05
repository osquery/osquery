// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/tables/system/darwin/firewall.h"

#include <glog/logging.h>

#include <boost/lexical_cast.hpp>

#include "osquery/database.h"
#include "osquery/filesystem.h"
#include "osquery/status.h"

using namespace osquery::db;
using osquery::Status;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kALFPlistPath = "/Library/Preferences/com.apple.alf.plist";

// it.first represents the key that is used in com.apple.alf.plist to identify
// the data in question. it.second represents the value of the "service" column
// in the alf_services table.
const std::map<std::string, std::string> kFirewallTreeKeys = {
    {"Apple Remote Desktop", "Apple Remote Desktop"},
    {"FTP Access", "FTP"},
    {"ODSAgent", "ODSAgent"},
    {"Personal File Sharing", "File Sharing"},
    {"Personal Web Sharing", "Web Sharing"},
    {"Printer Sharing", "Printer Sharing"},
    {"Remote Apple Events", "Remote Apple Events"},
    {"Remote Login - SSH", "SSH"},
    {"Samba Sharing", "Samba Sharing"}, };

// it.first represents the top level keys in com.apple.alf.plist to identify
// the data in question. it.second represents the names of the columns that
// each sample of data can be found under in the alf table.
const std::map<std::string, std::string> kTopLevelIntKeys = {
    {"allowsignedenabled", "allow_signed_enabled"},
    {"firewallunload", "firewall_unload"},
    {"globalstate", "global_state"},
    {"loggingenabled", "logging_enabled"},
    {"loggingoption", "logging_option"},
    {"stealthenabled", "stealth_enabled"}, };

// it.first represents the top level keys in com.apple.alf.plist to identify
// the data in question. it.second represents the names of the columns that
// each sample of data can be found under in the alf table.
const std::map<std::string, std::string> kTopLevelStringKeys = {
    {"version", "version"}, };

Status genALFTreeFromFilesystem(pt::ptree& tree) {
  try {
    Status s = osquery::fs::parsePlist(kALFPlistPath, tree);
    if (!s.ok()) {
      LOG(ERROR) << "Error parsing " << kALFPlistPath << ": " << s.toString();
      return s;
    }
  }
  catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

QueryData parseALFTree(const pt::ptree& tree) {
  Row r;

  for (const auto& it : kTopLevelIntKeys) {
    try {
      int val = tree.get<int>(it.first);
      r[it.second] = boost::lexical_cast<std::string>(val);
    }
    catch (const pt::ptree_error& e) {
      LOG(ERROR) << "Error retreiving " << it.second
                 << " from com.apple.alf: " << e.what();
    }
  }

  for (const auto& it : kTopLevelStringKeys) {
    try {
      std::string val = tree.get<std::string>(it.second);
      r[it.first] = val;
    }
    catch (const pt::ptree_error& e) {
      LOG(ERROR) << "Error retreiving " << it.second
                 << " from com.apple.alf: " << e.what();
    }
  }

  return {r};
}

QueryData genALF() {
  pt::ptree tree;
  auto s = genALFTreeFromFilesystem(tree);
  if (!s.ok()) {
    return {};
  }
  return parseALFTree(tree);
}

QueryData parseALFExceptionsTree(const pt::ptree& tree) {
  QueryData results;

  pt::ptree exceptions_tree;
  try {
    exceptions_tree = tree.get_child("exceptions");
  }
  catch (const pt::ptree_error& e) {
    LOG(ERROR) << "Error retrieving exceptions key: " << e.what();
    return {};
  }

  for (const auto& it : exceptions_tree) {
    std::string path;
    int state;
    try {
      path = it.second.get<std::string>("path");
      state = it.second.get<int>("state");
      Row r;
      r["path"] = path;
      r["state"] = boost::lexical_cast<std::string>(state);
      results.push_back(r);
    }
    catch (const pt::ptree_error& e) {
      LOG(ERROR) << "Error retrieving firewall exception keys: " << e.what();
    }
    catch (const boost::bad_lexical_cast& e) {
      LOG(ERROR) << "Error casting state (" << state << "): " << e.what();
    }
  }

  return results;
}

QueryData genALFExceptions() {
  pt::ptree tree;
  auto s = genALFTreeFromFilesystem(tree);
  if (!s.ok()) {
    return {};
  }
  return parseALFExceptionsTree(tree);
}

QueryData parseALFExplicitAuthsTree(const pt::ptree& tree) {
  QueryData results;

  pt::ptree auths_tree;
  try {
    auths_tree = tree.get_child("explicitauths");
  }
  catch (const pt::ptree_error& e) {
    LOG(ERROR) << "Error retrieving explicitauths key: " << e.what();
  }

  for (const auto& it : auths_tree) {
    std::string process;
    try {
      process = it.second.get<std::string>("id");
      Row r;
      r["process"] = process;
      results.push_back(r);
    }
    catch (const pt::ptree_error& e) {
      LOG(ERROR) << "Error retrieving firewall exception keys: " << e.what();
    }
  }

  return results;
}

QueryData genALFExplicitAuths() {
  pt::ptree tree;
  auto s = genALFTreeFromFilesystem(tree);
  if (!s.ok()) {
    return {};
  }
  return parseALFExplicitAuthsTree(tree);
}

QueryData parseALFServicesTree(const pt::ptree& tree) {
  QueryData results;
  pt::ptree firewall_tree;
  try {
    firewall_tree = tree.get_child("firewall");
  }
  catch (const pt::ptree_error& e) {
    LOG(ERROR) << "Error retrieving firewall key: " << e.what();
  }

  for (const auto& it : kFirewallTreeKeys) {
    std::string proc;
    int state;
    pt::ptree subtree;
    try {
      subtree = firewall_tree.get_child(it.first);
      proc = subtree.get<std::string>("proc");
      state = subtree.get<int>("state");
      Row r;
      r["service"] = it.second;
      r["process"] = proc;
      r["state"] = boost::lexical_cast<std::string>(state);
      results.push_back(r);
    }
    catch (const pt::ptree_error& e) {
      LOG(ERROR) << "Error retrieving " << it.first << " keys: " << e.what();
    }
    catch (const boost::bad_lexical_cast& e) {
      LOG(ERROR) << "Error casting state (" << state << "): " << e.what();
    }
  }
  return results;
}

QueryData genALFServices() {
  pt::ptree tree;
  auto s = genALFTreeFromFilesystem(tree);
  if (!s.ok()) {
    return {};
  }
  return parseALFServicesTree(tree);
}
}
}
