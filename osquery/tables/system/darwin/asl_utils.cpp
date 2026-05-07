/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/replace.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/tables/system/darwin/asl_utils.h>

namespace ba = boost::algorithm;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/**
 * @brief Map osquery ConstraintOperator to the corresponding ASL op code
 */
const std::map<ConstraintOperator, uint32_t> kSupportedAslOps = {
    {EQUALS, ASL_QUERY_OP_EQUAL},
    {GREATER_THAN, ASL_QUERY_OP_GREATER},
    {GREATER_THAN_OR_EQUALS, ASL_QUERY_OP_GREATER_EQUAL},
    {LESS_THAN, ASL_QUERY_OP_LESS},
    {LESS_THAN_OR_EQUALS, ASL_QUERY_OP_LESS_EQUAL},
    {LIKE, ASL_QUERY_OP_EQUAL | ASL_QUERY_OP_REGEX | ASL_QUERY_OP_CASEFOLD}};

/**
 * @brief Map ASL keys to the corresponding osquery column name
 */
const std::map<std::string, std::string> kAslKeyToColumnMap = {
    {"Time", "time"},
    {"TimeNanoSec", "time_nano_sec"},
    {"Host", "host"},
    {"Sender", "sender"},
    {"Facility", "facility"},
    {"PID", "pid"},
    {"UID", "uid"},
    {"GID", "gid"},
    {"Level", "level"},
    {"Message", "message"},
    {"RefPID", "ref_pid"},
    {"RefProc", "ref_proc"}};

/**
 * @brief Map osquery column names to the corresponding ASL keys
 */
const std::map<std::string, std::string> kColumnToAslKeyMap = {
    {"time", "Time"},
    {"time_nano_sec", "TimeNanoSec"},
    {"host", "Host"},
    {"sender", "Sender"},
    {"facility", "Facility"},
    {"pid", "PID"},
    {"uid", "UID"},
    {"gid", "GID"},
    {"level", "Level"},
    {"message", "Message"},
    {"ref_pid", "RefPID"},
    {"ref_proc", "RefProc"}};

/**
 * @brief Column name for the extra column.
 *
 * ASL allows fields not defined in asl.h to be sent with logs. These fields
 * will be aggregated into a JSON string and dumped into a column with this
 * name.
 */
const std::string kExtraColumnKey = "extra";

/**
 * @brief Determine whether to use numeric ASL operations given a column type
 */
static inline bool isNumeric(ColumnType coltype) {
  switch (coltype) {
  case INTEGER_TYPE:
  case BIGINT_TYPE:
  case UNSIGNED_BIGINT_TYPE:
  case DOUBLE_TYPE:
    return true;
  default:
    return false;
  }
}

// macOS ASL is deprecated in 10.12
_Pragma("clang diagnostic push");
_Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"");

void addQueryOp(aslmsg& query,
                const std::string& key,
                const std::string& value,
                ConstraintOperator op,
                ColumnType col_type) {
  if (key == kExtraColumnKey) {
    // ASL doesn't know about the 'Extra' column, so we can't do the matching
    // through the ASL query. Do nothing here, and later SQLite's engine will
    // do the match.
    return;
  }

  // Only some queries can be supported through ASL, those that are not will
  // just be performed later by the SQLite engine.
  if (kSupportedAslOps.count(op) > 0) {
    uint32_t asl_op = kSupportedAslOps.at(op);
    std::string modified_val = value;
    std::string modified_key = kColumnToAslKeyMap.at(key);
    switch (op) {
    case LIKE:
      // In the LIKE case, we need to convert the like string to a regex for
      // use in the ASL query
      modified_val = convertLikeRegex(value);
      break;
    default:
      if (isNumeric(col_type)) {
        asl_op |= ASL_QUERY_OP_NUMERIC;
      }
    }
    asl_set_query(query, modified_key.c_str(), modified_val.c_str(), asl_op);
  }
}

aslmsg createAslQuery(const QueryContext& context) {
  aslmsg query = asl_new(ASL_TYPE_QUERY);

  // Set constraints in query
  for (const auto& it : context.constraints) {
    const std::string& key = it.first;
    ColumnType col_type = it.second.affinity;
    for (const auto& constraint : it.second.getAll()) {
      addQueryOp(query,
                 key,
                 constraint.expr,
                 static_cast<ConstraintOperator>(constraint.op),
                 col_type);
    }
  }
  return query;
}

void readAslRow(aslmsg row, Row& r) {
  pt::ptree extras;

  // Fetch each column individually, adding it to the result map
  size_t i = 0;
  for (const char* key = asl_key(row, i); key != nullptr;
       key = asl_key(row, ++i)) {
    const char* val = asl_get(row, key);

    // Rarely, asl_fetch_key_val_op will return a NULL pointer for
    // key/value, so we defend against that case by using the empty string
    std::string key_s = key != nullptr ? std::string(key) : "";
    std::string val_s = val != nullptr ? std::string(val) : "";

    if (kAslKeyToColumnMap.count(key_s) > 0) {
      // This key is a default column
      r[kAslKeyToColumnMap.at(key_s)] = val_s;
    } else {
      // This key is not a default column, add it to extras
      extras.push_back(pt::ptree::value_type(key_s, pt::ptree(val_s)));
    }
  }

  // Join up the extras and add them to the Extra column
  std::stringstream ss;
  pt::write_json(ss, extras, false);
  r[kExtraColumnKey] = ss.str();
}

std::string convertLikeRegex(const std::string& like_str) {
  // % is equivalent to .*
  // _ is equivalent to .
  std::string res = ba::replace_all_copy(like_str, "%", ".*");
  ba::replace_all(res, "_", ".");
  return res;
}

_Pragma("clang diagnostic pop");
}
}
