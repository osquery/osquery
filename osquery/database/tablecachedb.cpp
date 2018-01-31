#include <osquery/tables.h>
#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/flags.h>

namespace osquery {

  // in dispatcher/scheduler
  extern size_t kCacheInterval;
  extern size_t kCacheStep;

  DECLARE_bool(disable_caching);

  class TableCacheDB : public TableCache
  {
  public:
    TableCacheDB(std::string tableName) : last_cached_(0), last_interval_(0), tableName_(tableName) {}
    virtual ~TableCacheDB() {}

    virtual bool isEnabled() const { return true; }

    virtual const std::string getTableName() const { return tableName_; }

    virtual bool isCached() const {
      if (FLAGS_disable_caching) {
        return false;
      }

      // Perform the step comparison first, because it's easy.
      return (kCacheStep < last_cached_ + last_interval_ );
    }

    virtual QueryData get() const {
      VLOG(1) << "Retrieving results from cache for table: " << getTableName();
      // Lookup results from database and deserialize.
      std::string content;
      getDatabaseValue(kQueries, "cache." + getTableName(), content);
      QueryData results;
      deserializeQueryDataJSON(content, results);
      return results;
    }

    void set(const QueryData& results) {
      if (FLAGS_disable_caching) {
        return;
      }

      // Serialize QueryData and save to database.
      std::string content;
      if (serializeQueryDataJSON(results, content)) {
        last_cached_ = kCacheStep;
        last_interval_ = kCacheInterval;
        setDatabaseValue(kQueries, "cache." + getTableName(), content);
      }
    }
  private:
    size_t last_cached_ {0};
    size_t last_interval_ {0};
    std::string tableName_;
  };

  TableCache* TableCacheDBNew(std::string tableName) { return new TableCacheDB(tableName); }

}
