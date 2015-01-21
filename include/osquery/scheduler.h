/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/database/results.h>

namespace osquery {

/**
 * @brief represents the relevant parameters of a scheduled query.
 *
 * Within the context of osqueryd, a scheduled query may have many relevant
 * attributes. Those attributes are represented in this data structure.
 */
struct OsqueryScheduledQuery {
  /// name represents the "name" of a query.
  std::string name;

  /// query represents the actual SQL query.
  std::string query;

  /// interval represents how often the query should be executed, in minutes.
  int interval;

  /// equals operator
  bool operator==(const OsqueryScheduledQuery& comp) const {
    return (comp.name == name) && (comp.query == query) &&
           (comp.interval == interval);
  }

  /// not equals operator
  bool operator!=(const OsqueryScheduledQuery& comp) const {
    return !(*this == comp);
  }
};

/////////////////////////////////////////////////////////////////////////////
// ScheduledQueryLogItem
/////////////////////////////////////////////////////////////////////////////

/**
 * @brief A data structure which represents data to log in the event of an
 * operating system state change
 *
 * When a scheduled query yields new results, we need to log that information
 * to our upstream logging receiver. The data that needs to be logged is the
 * entire DiffResults set as well as some additional metadata.
 */
struct ScheduledQueryLogItem {
  /// The data which was changed as a result of the scheduled query
  DiffResults diffResults;

  /// The name of the scheduled query
  std::string name;

  /// The identifier (hostname, or uuid) of the host on which the query was
  /// executed
  std::string hostIdentifier;

  /// The time that the query was executed, in unix time
  int unixTime;

  /// The time that the query was executed, in ASCII
  std::string calendarTime;

  /// equals operator
  bool operator==(const ScheduledQueryLogItem& comp) const {
    return (comp.diffResults == diffResults) && (comp.name == name);
  }

  /// not equals operator
  bool operator!=(const ScheduledQueryLogItem& comp) const {
    return !(*this == comp);
  }
};

/**
 * @brief Serialize a ScheduledQueryLogItem object into a property tree
 *
 * @param i the ScheduledQueryLogItem to serialize
 * @param tree a reference to a property tree which, if all operations are
 * completed successfully, the contents of ScheduledQueryLogItem will be
 * serialized into
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation
 */
Status serializeScheduledQueryLogItem(const ScheduledQueryLogItem& i,
                                      boost::property_tree::ptree& tree);

/**
 * @brief Serialize a ScheduledQueryLogItem object into a JSON string
 *
 * @param i the ScheduledQueryLogItem to serialize
 * @param json a reference to a string which, if all operations are completed
 * successfully, the contents of ScheduledQueryLogItem will be serialized into
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation
 */
Status serializeScheduledQueryLogItemJSON(const ScheduledQueryLogItem& i,
                                          std::string& json);

/**
 * @brief Serialize a ScheduledQueryLogItem object into a property tree
 * of events, a list of actions.
 *
 * @param item the ScheduledQueryLogItem to serialize
 * @param tree a reference to a property tree which, if all operations are
 * completed successfully, the contents of ScheduledQueryLogItem will be
 * serialized into
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation
 */
Status serializeScheduledQueryLogItemAsEvents(
    const ScheduledQueryLogItem& item, boost::property_tree::ptree& tree);

/**
 * @brief Serialize a ScheduledQueryLogItem object into a JSON string of events,
 * a list of actions.
 *
 * @param i the ScheduledQueryLogItem to serialize
 * @param json a reference to a string which, if all operations are completed
 * successfully, the contents of ScheduledQueryLogItem will be serialized into
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation
 */
Status serializeScheduledQueryLogItemAsEventsJSON(
    const ScheduledQueryLogItem& i, std::string& json);

/**
 * @brief Launch the scheduler.
 *
 * osquery comes with a scheduler, which schedules a variety of things. This
 * is one of the core parts of the osqueryd daemon. To use this, simply use
 * this function as your entry point when creating a new thread.
 *
 * @code{.cpp}
 *   boost::thread scheduler_thread(osquery::initializeScheduler);
 *   // do some other stuff
 *   scheduler_thread.join();
 * @endcode
 */
void initializeScheduler();

/**
 * @brief Calculate a splayed integer based on a variable splay percentage
 *
 * The value of splayPercent must be between 1 and 100. If it's not, the
 * value of original will be returned.
 *
 * @param original The original value to be modified
 * @param splayPercent The percent in which to splay the original value by
 *
 * @return The modified version of original
 */
int splayValue(int original, int splayPercent);
}
