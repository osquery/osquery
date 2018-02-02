#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {

DECLARE_bool(disable_caching);

// the following static globals are manipulated by scheduler (and tests)
// to reflect time and scheduled query interval
size_t kTableCacheInterval = 0;
size_t kTableCacheStep = 0;

class TableCacheDB : public TableCache {
 public:
  /* constructor should primarily be called from TableCacheNew()
   */
  TableCacheDB(std::string tableName)
      : last_cached_(0), last_interval_(0), tableName_(tableName) {}
  virtual ~TableCacheDB() {}

  /*
   * returns true if this is a TableCache implementation that can persist
   * results. Only TableCacheDisabled should return false.
   */
  virtual bool isEnabled() const {
    return true;
  }

  virtual const std::string getTableName() const {
    return tableName_;
  }

  virtual bool isCached() const {
    if (FLAGS_disable_caching) {
      return false;
    }

    // Perform the step comparison first, because it's easy.
    return (kTableCacheStep < last_cached_ + last_interval_);
  }

  /*
   * fetch results from store, deserialize, and return.
   */
  virtual QueryData get() const {
    VLOG(1) << "Retrieving results from cache for table: " << getTableName();
    // Lookup results from database and deserialize.
    std::string content;
    getDatabaseValue(kQueries, "cache." + getTableName(), content);
    QueryData results;
    deserializeQueryDataJSON(content, results);
    return results;
  }

  /*
   * if FLAGS_disable_caching is false, then serializes and stores data.
   * Snapshots kTableCacheStep and kTableCacheInterval to ensure
   * stays valid for desired time.
   */
  void set(const QueryData& results) {
    if (FLAGS_disable_caching) {
      return;
    }

    // Serialize QueryData and save to database.
    std::string content;
    if (serializeQueryDataJSON(results, content)) {
      last_cached_ = kTableCacheStep;
      last_interval_ = kTableCacheInterval;
      setDatabaseValue(kQueries, "cache." + getTableName(), content);
    }
  }

 private:
  size_t last_cached_{0};
  size_t last_interval_{0};
  std::string tableName_;
};

TableCache* TableCacheDBNew(std::string tableName) {
  return new TableCacheDB(tableName);
}

TableCache* TableCacheNew(std::string tableName, bool isCacheable) {
  if (!isCacheable)
    return new TableCacheDisabled(tableName);
  return new TableCacheDB(tableName);
}

} // namespace osquery
