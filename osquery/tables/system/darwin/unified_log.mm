/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <OSLog/OSLog.h>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>

#include <boost/algorithm/string/replace.hpp>
namespace ba = boost::algorithm;

namespace osquery {
namespace tables {

const std::map<ConstraintOperator, NSPredicateOperatorType> kSupportedOps = {
    {EQUALS, NSEqualToPredicateOperatorType},
    {GREATER_THAN, NSGreaterThanPredicateOperatorType},
    {GREATER_THAN_OR_EQUALS, NSGreaterThanOrEqualToPredicateOperatorType},
    {LESS_THAN, NSLessThanPredicateOperatorType},
    {LESS_THAN_OR_EQUALS, NSLessThanOrEqualToPredicateOperatorType},
    {LIKE, NSLikePredicateOperatorType}};

const std::map<std::string, std::string> kColumnToOSLogEntryProp = {
    {"timestamp", "date"},
    {"message", "composedMessage"},
    {"storage", "storeCategory"},
    {"activity", "activityIdentifier"},
    {"process", "process"},
    {"pid", "processIdentifier"},
    {"sender", "sender"},
    {"tid", "threadIdentifier"},
    {"subsystem", "subsystem"},
    {"category", "category"}};

const std::map<std::string, bool> kColumnIsNumeric = {{"timestamp", false},
                                                      {"message", false},
                                                      {"storage", true},
                                                      {"activity", true},
                                                      {"process", false},
                                                      {"pid", true},
                                                      {"sender", false},
                                                      {"tid", true},
                                                      {"subsystem", false},
                                                      {"category", false}};

/**
 * @brief The backing store keys for saving the lst data extracted.
 */
const std::string kUALtimestampKey{"ual_timestamp"};
const std::string kUALcountKey{"ual_counter"};

/**
 * @brief maximum rows configuration filter
 */
const int kMaxRowsDefault = 100;
const std::string kMaxRowsColumn = "max_rows";
const ConstraintOperator kMaxRowsOperator = EQUALS;

/**
 * @brief timestamp sequential configuration filter
 */
const std::string kSentinelColumn = "timestamp";
const std::string kSentinelValue = "-1";
const ConstraintOperator kSentinelOperator = GREATER_THAN;

/**
 * @brief defines the structure that saves the current status for extracting
 *        sequential data in multiple queries
 */
struct SequentialContext {
  double timestamp; /**< timestamp of last log, used as a pointer */
  int count; /**< if two or more logs has the same timestamp,
                  the API will return a pointer to the first one,
                  save how many we extracted so we can skip to the
                  current*/

  SequentialContext() : timestamp(0), count(0) {}

  /**
   * @brief load values from database in case there are stored
   */
  void load();

  /**
   * @brief saves values into database
   */
  void save();
};

void SequentialContext::load() {
  std::string str;
  auto s = getDatabaseValue(kPersistentSettings, kUALtimestampKey, str);
  if (s.ok())
    timestamp = std::stod(str);
  s = getDatabaseValue(kPersistentSettings, kUALcountKey, str);
  if (s.ok())
    count = std::stoi(str);
}

void SequentialContext::save() {
  std::string str = std::to_string(timestamp);
  auto s = setDatabaseValue(kPersistentSettings, kUALtimestampKey, str);
  if (!s.ok())
    VLOG(1)
        << "Failed to update ual_timestamp of persistent settings in database";
  str = std::to_string(count);
  s = setDatabaseValue(kPersistentSettings, kUALcountKey, str);
  if (!s.ok())
    VLOG(1)
        << "Failed to update ual_counter of persistent settings in database";
}

std::string convertLikeExpr(const std::string& value) {
  // for the LIKE operator in NSPredicates, '*' matches 0 or more characters
  //   and '?' matches a single character
  std::string res = ba::replace_all_copy(value, "%", "*");
  ba::replace_all(res, "_", "?");
  return res;
}

void addQueryOp(NSMutableArray* preds,
                const std::string& key,
                const std::string& value,
                ConstraintOperator op) {
  if (kSupportedOps.count(op) > 0 && kColumnToOSLogEntryProp.count(key) > 0) {
    std::string modified_val = value;
    std::string modified_key = kColumnToOSLogEntryProp.at(key);
    if (op == LIKE) {
      modified_val = convertLikeExpr(value);
    }
    NSExpression* keyExp = [NSExpression
        expressionForKeyPath:[NSString
                                 stringWithUTF8String:modified_key.c_str()]];
    NSString* valStr = [NSString stringWithUTF8String:modified_val.c_str()];

    NSExpression* valExp = nil;
    if (key == "timestamp") {
      double provided_timestamp = [valStr doubleValue];
      valExp = [NSExpression
          expressionForConstantValue:
              [NSDate dateWithTimeIntervalSince1970:provided_timestamp]];
    } else if (kColumnIsNumeric.at(key)) {
      valExp =
          [NSExpression expressionWithFormat:@"%lld", [valStr longLongValue]];
    } else {
      valExp = [NSExpression expressionForConstantValue:valStr];
    }

    NSPredicate* pred = [NSComparisonPredicate
        predicateWithLeftExpression:keyExp
                    rightExpression:valExp
                           modifier:NSDirectPredicateModifier
                               type:kSupportedOps.at(op)
                            options:0];
    [preds addObject:pred];
  }
}

/**
 * @brief search into the context for a max rows configuration
 *
 * @param queryContext current context
 *
 * @returns the number of maximum rows configured
 */
int getMaxRows(QueryContext& queryContext) {
  if (queryContext.hasConstraint(kMaxRowsColumn, kMaxRowsOperator)) {
    auto const max_rows = tryTo<int>(*queryContext.constraints[kMaxRowsColumn]
                                          .getAll(kMaxRowsOperator)
                                          .begin());
    if (max_rows.isValue())
      return max_rows.get();
  }
  return kMaxRowsDefault;
}

/**
 * @brief search into the context for a sequential timestamp configuration
 *
 * @param queryContext current context
 *
 * @returns true if sequential configuration has been triggered
 * @returns false otherwise
 */
bool getSequential(QueryContext& queryContext) {
  if (queryContext.hasConstraint(kSentinelColumn, kSentinelOperator)) {
    std::string str;
    str = *queryContext.constraints[kSentinelColumn]
               .getAll(kSentinelOperator)
               .begin();
    return str == kSentinelValue;
  }
  return false;
}

bool badSentinel(QueryContext& queryContext) {
  if (queryContext.hasConstraint(kSentinelColumn)) {
    std::string str;

    for (const auto& it : queryContext.constraints) {
      const std::string& key = it.first;
      if (key != kSentinelColumn)
        continue;
      for (const auto& constraint : it.second.getAll()) {
        if (constraint.op != GREATER_THAN &&
            constraint.op != GREATER_THAN_OR_EQUALS) {
          auto const timestamp_expr = tryTo<int>(constraint.expr);
          if (timestamp_expr.isValue() && timestamp_expr.get() < 0)
            return true;
        }
      }
    }
  }
  return false;
}

QueryData genUnifiedLog(QueryContext& queryContext) {
  QueryData results;
  if (@available(macOS 10.15, *)) {
    int rows_counter = 0;
    SequentialContext sc;

    @autoreleasepool {
      NSError* error = nil;
      OSLogStore* logstore = [OSLogStore localStoreAndReturnError:&error];
      if (error != nil) {
        TLOG << "error getting handle to log store: "
             << [[error localizedDescription] UTF8String];
        return {};
      }

      if (badSentinel(queryContext)) {
        TLOG << "error on timestamp constraint";
        return {};
      }

      OSLogPosition* position = nil;

      sc.load();
      int max_rows = getMaxRows(queryContext);
      bool isSequential = getSequential(queryContext);

      // the timestamp column can be used to aggressively filter
      // results returned from the log store
      if (!isSequential &&
          (queryContext.hasConstraint("timestamp", GREATER_THAN) ||
           queryContext.hasConstraint("timestamp", GREATER_THAN_OR_EQUALS))) {
        std::string start_time;
        if (queryContext.hasConstraint("timestamp", GREATER_THAN)) {
          start_time = *queryContext.constraints["timestamp"]
                            .getAll(GREATER_THAN)
                            .begin();
        } else {
          start_time = *queryContext.constraints["timestamp"]
                            .getAll(GREATER_THAN_OR_EQUALS)
                            .begin();
        }

        double provided_timestamp =
            [[NSString stringWithUTF8String:start_time.c_str()] doubleValue];
        NSDate* provided_date =
            [NSDate dateWithTimeIntervalSince1970:provided_timestamp];

        position = [logstore positionWithDate:provided_date];
      }

      // grab all the supported columns used in simple constraints and make a
      // compound predicate out of them.
      NSMutableArray* subpredicates = [[NSMutableArray alloc] init];
      for (const auto& it : queryContext.constraints) {
        const std::string& key = it.first;
        for (const auto& constraint : it.second.getAll()) {
          if (key == kSentinelColumn && constraint.expr == kSentinelValue &&
              constraint.op == kSentinelOperator)
            continue;
          addQueryOp(subpredicates,
                     key,
                     constraint.expr,
                     static_cast<ConstraintOperator>(constraint.op));
        }
      }

      NSPredicate* predicate =
          [NSCompoundPredicate andPredicateWithSubpredicates:subpredicates];

      // Apply sequential extraction
      if (isSequential) {
        NSDate* last_date = [NSDate dateWithTimeIntervalSince1970:sc.timestamp];
        position = [logstore positionWithDate:last_date];
      }

      // enumerate the entries in ascending order by timestamp
      OSLogEnumeratorOptions option = 0;

      OSLogEnumerator* enumerator =
          [logstore entriesEnumeratorWithOptions:option
                                        position:position
                                       predicate:predicate
                                           error:&error];
      if (error != nil) {
        TLOG << "error enumerating entries in system log: "
             << [[error localizedDescription] UTF8String];
        return {};
      }

      int skip_counter = 0;
      bool first = isSequential;
      for (OSLogEntryLog* entry in enumerator) {
        if (first) {
          // Skips the log entries that have been already extracted
          double load_date = [[entry date] timeIntervalSince1970];
          if (load_date == sc.timestamp) {
            if (++skip_counter <= sc.count) {
              continue;
            }
          }
          first = false;
        }

        if (isSequential) {
          // Save timestamp and count
          double load_date = [[entry date] timeIntervalSince1970];
          if (sc.timestamp == load_date) {
            sc.count++;
          } else {
            sc.count = 0;
            sc.timestamp = load_date;
          }
        }

        // Escape if the rows number reached the limit
        if (++rows_counter > max_rows)
          break;

        Row r;

        r["timestamp"] = BIGINT([[entry date] timeIntervalSince1970]);
        r["message"] = SQL_TEXT(
            std::string([[entry composedMessage] UTF8String],
                        [[entry composedMessage]
                            lengthOfBytesUsingEncoding:NSUTF8StringEncoding]));
        r["storage"] = INTEGER([entry storeCategory]);

        if ([entry respondsToSelector:@selector(activityIdentifier)]) {
          r["activity"] = BIGINT([entry activityIdentifier]);
          r["process"] = SQL_TEXT(std::string(
              [[entry process] UTF8String],
              [[entry process]
                  lengthOfBytesUsingEncoding:NSUTF8StringEncoding]));
          r["pid"] = BIGINT([entry processIdentifier]);
          r["sender"] = SQL_TEXT(std::string(
              [[entry sender] UTF8String],
              [[entry sender]
                  lengthOfBytesUsingEncoding:NSUTF8StringEncoding]));
          r["tid"] = BIGINT([entry threadIdentifier]);
        }

        if ([entry respondsToSelector:@selector(subsystem)]) {
          NSString* subsystem = [entry subsystem];
          if (subsystem != nil) {
            r["subsystem"] = SQL_TEXT(std::string(
                [[entry subsystem] UTF8String],
                [[entry subsystem]
                    lengthOfBytesUsingEncoding:NSUTF8StringEncoding]));
          }
          NSString* category = [entry category];
          if (category != nil) {
            r["category"] = SQL_TEXT(std::string(
                [[entry category] UTF8String],
                [[entry category]
                    lengthOfBytesUsingEncoding:NSUTF8StringEncoding]));
          }
        }

        if ([entry respondsToSelector:@selector(level)]) {
          std::vector<std::string> log_levels{
              "undefined", "debug", "info", "default", "error", "fault"};
          try {
            r["level"] = log_levels.at([entry level]);
          } catch (const std::out_of_range& oor) {
            LOG(WARNING) << "Unknown log value: " << [entry level];
            r["level"] = SQL_TEXT("unknown log level");
          }
        }
        // sqlite engine will apply the filter max_rows = N
        r["max_rows"] = INTEGER(max_rows);
        results.push_back(r);
      }
      sc.save();
    }
  } else {
    VLOG(1) << "OSLog framework is not available";
  }

  return results;
}
} // namespace tables
} // namespace osquery
