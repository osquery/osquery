// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/devtools.h"

#include <iostream>
#include <sstream>

#include <glog/logging.h>

#include "osquery/core.h"

namespace osquery {

std::string beautify(const QueryData& q,
                     const std::vector<std::string>& order) {
  auto lengths = computeQueryDataLengths(q);

  if (q.size() == 0) {
    return std::string();
  }

  auto separator = generateSeparator(lengths, order);
  std::ostringstream results;
  results << "\n";

  results << separator;
  results << generateHeader(lengths, order);
  results << separator;
  for (const auto& r : q) {
    results << generateRow(r, lengths, order);
  }
  results << separator;

  return results.str();
}

std::string generateSeparator(const std::map<std::string, int>& lengths,
                              const std::vector<std::string>& order) {
  std::ostringstream separator;

  separator << "+";
  for (const auto& each : order) {
    try {
      for (int i = 0; i < lengths.at(each) + 2; ++i) {
        separator << "-";
      }
    } catch (const std::out_of_range& e) {
      LOG(ERROR) << "Error retrieving the \"" << each
                 << "\" key in generateSeparator:  " << e.what();
    }
    separator << "+";
  }
  separator << "\n";

  return separator.str();
}

std::string generateHeader(const std::map<std::string, int>& lengths,
                           const std::vector<std::string>& order) {
  std::ostringstream header;

  header << "|";
  for (const auto& each : order) {
    header << " ";
    header << each;
    try {
      for (int i = 0; i < (lengths.at(each) - utf8StringSize(each) + 1); ++i) {
        header << " ";
      }
    } catch (const std::out_of_range& e) {
      LOG(ERROR) << "Error retrieving the \"" << each
                 << "\" key in generateHeader:  " << e.what();
    }
    header << "|";
  }
  header << "\n";

  return header.str();
}

std::string generateRow(const Row& r,
                        const std::map<std::string, int>& lengths,
                        const std::vector<std::string>& order) {
  std::ostringstream row;

  row << "|";
  for (const auto& each : order) {
    row << " ";
    try {
      row << r.at(each);
      for (int i = 0; i < (lengths.at(each) - utf8StringSize(r.at(each)) + 1);
           ++i) {
        row << " ";
      }
    } catch (const std::out_of_range& e) {
      LOG(ERROR) << "printing the faulty row";
      for (const auto& foo : r) {
        LOG(ERROR) << foo.first << " => " << foo.second;
      }
      LOG(ERROR) << "Error retrieving the \"" << each
                 << "\" key in generateRow:  " << e.what();
    }
    row << "|";
  }
  row << "\n";

  return row.str();
}

void prettyPrint(const QueryData& q, const std::vector<std::string>& order) {
  std::cout << beautify(q, order);
}

std::map<std::string, int> computeQueryDataLengths(const QueryData& q) {
  std::map<std::string, int> results;

  if (q.size() == 0) {
    return results;
  }

  for (const auto& it : q.front()) {
    results[it.first] = utf8StringSize(it.first);
  }

  for (const auto& row : q) {
    for (const auto& it : row) {
      try {
        auto s = utf8StringSize(it.second);
        if (s > results[it.first]) {
          results[it.first] = s;
        }
      } catch (const std::out_of_range& e) {
        LOG(ERROR) << "Error retrieving the \"" << it.first
                   << "\" key in computeQueryDataLength:  " << e.what();
      }
    }
  }

  return results;
}
}
