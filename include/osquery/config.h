// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "osquery/status.h"

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

/**
 * @brief A native representation of osquery configuration data.
 *
 * When you use osquery::Config::getInstance(), you are getting a singleton
 * handle to interact with the data stored in an instance of this struct.
 */
struct OsqueryConfig {
  /// A vector of all of the queries that are scheduled to execute.
  std::vector<OsqueryScheduledQuery> scheduledQueries;
};

/**
 * @brief A string which represents the default consfig retriever.
 *
 * The config plugin that you use to define your config retriever can be
 * defined via a command-line flag, however, if you don't define a config
 * plugin to use via the command-line, then the config retriever which is
 * represented by the string stored in kDefaultConfigRetriever will be used.
 */
extern const std::string kDefaultConfigRetriever;

/**
 * @brief A singleton that exposes accessors to osquery's configuration data.
 *
 * osquery has two types on configurations. Things that don't change during
 * the execution of the process should be configured as command-line
 * arguments. Things that can change during the lifetime of program execution
 * should be defined using the osquery::config::Config class and the pluggable
 * plugin interface that is included with it.
 */
class Config {
 public:
  /**
   * @brief The primary way to access the Config singleton.
   *
   * osquery::config::Config::getInstance() provides access to the Config
   * singleton
   *
   * @code{.cpp}
   *   auto config = osquery::config::Config::getInstance();
   * @endcode
   *
   * @return a singleton instance of Config.
   */
  static std::shared_ptr<Config> getInstance();

  /**
   * @brief Get a vector of all scheduled queries.
   *
   * @code{.cpp}
   *   auto config = osquery::config::Config::getInstance();
   *   for (const auto& q : config->getScheduledQueries()) {
   *     LOG(INFO) << "name:     " << q.name;
   *     LOG(INFO) << "interval: " << q.interval;
   *   }
   * @endcode
   *
   * @return a vector of OsqueryScheduledQuery's which represent the queries
   * that are to be executed
   */
  std::vector<OsqueryScheduledQuery> getScheduledQueries();

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
  static int splayValue(int original, int splayPercent);

 private:
  /**
   * @brief Default constructor.
   *
   * Since instances of Config should only be created via getInstance(),
   * Config's constructor is private
   */
  Config();

  /**
   * @brief Uses the specified config retriever to populate a config struct.
   *
   * Internally, genConfig checks to see if there was a config retriever
   * specified on the command-line. If there was, it checks to see if that
   * config retriever actually exists. If it does, it gets used to generate
   * configuration data. If it does not, an error is logged.
   *
   * If no config retriever was specified, the config retriever represented by
   * kDefaultConfigRetriever is used.
   *
   * @param conf a reference to a struct which will be populated by the config
   * retriever in use.
   *
   * @return an instance of osquery::Status, indicating the success or failure
   * of the operation.
   */
  static osquery::Status genConfig(OsqueryConfig& conf);

 private:
  /**
   * @brief the private member that stores the raw osquery config data in a
   * native format
   */
  OsqueryConfig cfg_;
};
}
