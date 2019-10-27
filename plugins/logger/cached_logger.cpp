#include <algorithm>
#include <chrono>
#include <thread>

#include <boost/lexical_cast.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/dispatcher.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/flags.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/utils/info/version.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>
#include <plugins/config/parsers/decorators.h>

#include "plugins/logger/cached_logger.h"

// How often to check for files to send (default only)
#define DEFAULT_INTERVAL_SEC 30

#define STAT_REPORT_INTERVAL_SEC 300 // 5 minutes

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

FLAG(bool,
     cached_logger_stats,
     false,
     "Enable WARNING status logging of stats every 5-minutes.");

FLAG(bool,
    cached_logger_audit_trail,
    false,
    "Enable saving a local copy of all results logs for QA");

FLAG(uint64,
    cached_logger_max_files,
    7500,
    "In case of connectivity issue, will stop logging if number of files reaches limit.");

// this should be part of CachedLoggerPlugin, but didn't want to muddy up
// header file.
static RecursiveMutex mutex_;

static const std::string LOGGER_AUDIT_TRAIL_DIR = "z_cached_logger_audit";
static const std::string LOGGER_FAILED_DIR = "z_cached_logger_failed";
static const std::string LOGGER_CACHE_DIR = "z_cached_logs";

DECLARE_string(database_path);

  struct LoggerStats {
    uint64_t results_records_written;
    uint64_t results_records_sent;
    uint64_t results_files_written;
    uint64_t results_files_sent;
    uint64_t status_records_written;
    uint64_t status_records_sent;
    uint64_t status_files_written;
    uint64_t status_files_sent;
    uint64_t results_log_errors;
    uint64_t status_log_errors;
    uint64_t num_files_failed_to_send;
  };

  static LoggerStats gStats;
  static LoggerStats gStatsLast;
  static time_t gLastStatTime = 0;


class ForwarderThread : public InternalRunnable {
 public:
  ForwarderThread(CachedLoggerPlugin& logger,
                  std::shared_ptr<Forwarder> forwarder,
                  uint32_t interval_seconds,
                  uint32_t burst_file_count,
                  uint32_t burst_sleep_millis)
      : InternalRunnable(logger.name()),
        logger_(logger),
        forwarder_(forwarder),
        interval_seconds_(interval_seconds),
        burst_file_count_(burst_file_count),
        burst_sleep_millis_(burst_sleep_millis) {
    if (interval_seconds_ < 8 || interval_seconds_ > 3600) {
      interval_seconds_ = DEFAULT_INTERVAL_SEC;
    }
    interval_duration_ = std::chrono::seconds(interval_seconds_);
  }
  ~ForwarderThread() {}

 protected:
  virtual void start() override {

    while (!interrupted()) {
      std::vector<std::string> file_paths;
      logger_.getCachedFiles(file_paths, burst_file_count_);
      for (int i = 0; i < (int)file_paths.size(); i++) {
        if (i > 0) {
          pause(std::chrono::milliseconds(burst_sleep_millis_));
        }
        Status status = forwarder_->send(file_paths[i]);
        if (!status.ok() &&
            status.getCode() == FORWARDER_STATUS_NO_CONNECTION) {
          LOG(WARNING) << "network connection down or need to reauth";
          pause(std::chrono::seconds(30));
          break;
        }
        logger_.removeCachedFile(file_paths[i],
          status.ok() || status.getCode() == FORWARDER_STATUS_EMPTY_FILE);
      }

      // Cool off and time wait the configured period.
      pause(interval_duration_);
    }
  }

  CachedLoggerPlugin& logger_;
  std::shared_ptr<Forwarder> forwarder_;
  uint32_t interval_seconds_;
  uint32_t burst_file_count_;
  uint32_t burst_sleep_millis_;
  std::chrono::seconds interval_duration_;
};

/**
 * Call this at end of setUp() in any inherited classes.
 */
void CachedLoggerPlugin::start(std::shared_ptr<Forwarder> forwarder,
                               uint32_t interval_seconds,
                               uint32_t burst_file_count,
                               uint32_t burst_sleep_millis) {

  // make sure deadletter director exists

  createDirectory((fs::path(cache_path_) / LOGGER_CACHE_DIR).make_preferred(), false, true);
  createDirectory((fs::path(cache_path_) / LOGGER_FAILED_DIR).make_preferred(), false, true);

  if (FLAGS_cached_logger_audit_trail) {
    createDirectory((fs::path(cache_path_) / LOGGER_AUDIT_TRAIL_DIR).make_preferred(), false, true);
  }

  // start forwarder thread

  auto fthread = new ForwarderThread(
      *this, forwarder, interval_seconds, burst_file_count, burst_sleep_millis);
  forwarderThread_ = std::shared_ptr<InternalRunnable>(fthread);
  Dispatcher::addService(forwarderThread_);
}

/**
 * important : override tearDown so forwarderThread_ can be interrupted.
 * Otherwise, agent may not exit.  Also closes channel file handles.
 */
void CachedLoggerPlugin::tearDown() {
  if (forwarderThread_ != nullptr) {
    forwarderThread_->interrupt();
  }
  if (results_channel_.fp != nullptr) {
    fclose(results_channel_.fp);
    if (results_channel_.num_lines == 0) {
      removePath(fs::path(results_channel_.filepath).make_preferred());
    }
  }
  if (status_channel_.fp != nullptr) {
    fclose(status_channel_.fp);
    if (status_channel_.num_lines == 0) {
      removePath(fs::path(status_channel_.filepath).make_preferred());
    }
  }
}

/**
 * Call this first from from setUp() of any inherited classes.
 * If useSeparateStatusChannel == true, status log entries will be
 * cached and sent separately from results.
 */
void CachedLoggerPlugin::setProps(std::string logname,
                                  bool useSeparateStatusChannel,
                                  const LoggerBounds bounds) {
  bounds_ = bounds;
  results_channel_.prefix = "z_R_" + logname + "_";
  status_channel_.prefix = "z_S_" + logname + "_";
  results_channel_.isResult = true;
  status_channel_.isResult = false;

  cache_path_ = fs::path(FLAGS_database_path).make_preferred().string();

  if (pathExists(cache_path_).ok() && !isReadable(cache_path_).ok()) {
    LOG(ERROR) << "ERROR: Cannot read cache path: " << cache_path_;
    cache_path_ = "";
    return;
  }

  createDirectory((fs::path(cache_path_) / LOGGER_CACHE_DIR).make_preferred(), false, true);

  _enumerateExistingFiles();

  useSeparateStatusChannel_ = useSeparateStatusChannel;

  _rotateLog(results_channel_);
  if (useSeparateStatusChannel) {
    _rotateLog(status_channel_);
  }
}

/**
 * @returns true if the channel file should be closed, and a new file started.
 * Considers:
 *   - channel.num_bytes + line_length > bounds.max_bytes_per_batch
 *   - channel.num_lines + 1 > bounds.max_records_per_batch
 *   - (now - channel.ts > ROTATE_INTERVAL_SEC) and num_files_queued < 6
 * This function should be treated as private. (static + public for unit test)
 */
bool CachedLoggerPlugin::_needsRotate(LoggerBounds bounds,
                                      LogChannel& channel,
                                      time_t now,
                                      size_t line_length,
                                      size_t num_files_queued) {
  if (channel.num_lines == 0) {
    return false;
  }

  // if we are backed-up in sending, rely on bounds.
  // Otherwise, send every ROTATE_INTERVAL_SEC
  if (num_files_queued < 6 && (now - channel.ts) > ROTATE_INTERVAL_SEC) {
    return true;
  }

  if ((channel.num_bytes + line_length) >= bounds.max_bytes_per_batch ||
      ((channel.num_lines + 1) > bounds.max_records_per_batch)) {
    return true;
  }
  return false;
}

/**
 * _logStringInternal() is used by logString() and logStatus().
 * It holds the mutex, checks bounds, does _rotateLog if needed,
 * increments channel counters, and writes to file.
 */
Status CachedLoggerPlugin::_logStringInternal(LogChannel& channel,
                                              const std::string& s,
                                              bool isResult) {
  RecursiveLock lock(mutex_);
  if (nullptr == channel.fp || cacheLimitReached_ ) {
    return Status();
  }

  if (s.size() >= bounds_.max_bytes_per_record) {
    LOG(ERROR) << "unable to log. size: " << s.size()
               << " transport max:" << bounds_.max_bytes_per_record;
    if (isResult) {
      gStats.results_log_errors++;
    } else {
      gStats.status_log_errors++;
    }
    return Status();
  }

  bool didRotate = false;
  if (_needsRotate(
          bounds_, channel, time(NULL), s.size(), files_to_forward_.size())) {
    _rotateLog(channel);
    didRotate = true;
    if (channel.fp == nullptr) {
      return Status();
    }
  }

  channel.num_lines++;
  channel.num_bytes += s.size();

  if (isResult) {
    gStats.results_records_written++;
  } else {
    gStats.status_records_written++;
  }

  fputs(s.c_str(), channel.fp);
  fputs("\n", channel.fp);

  // With normal config (WARNING and ERROR status only), status lines are
  // infrequent.  So when we rotate results, also rotate status if needed.

  if (isResult && didRotate && useSeparateStatusChannel_ && status_channel_.num_bytes > 0) {
      _rotateLog(status_channel_);
  }

  return Status();
}

// standard logger entrypoint overrides

Status CachedLoggerPlugin::logString(const std::string& s) {
  return _logStringInternal(results_channel_, s, true);
}

/*
Status CachedLoggerPlugin::logStringBatch(std::vector<std::string>& items) {
  for (const auto& s : items) {
    logString(s);
  }
  return Status();
}*/

Status CachedLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  // Append decorations to status
  // Assemble a decorations tree to append to each status buffer line.
  pt::ptree dtree;
  std::map<std::string, std::string> decorations;
  getDecorations(decorations);
  for (const auto& decoration : decorations) {
    dtree.put(decoration.first, decoration.second);
  }

  for (const auto& item : log) {
    // Convert the StatusLogLine into ptree format, to convert to JSON.
    pt::ptree buffer;
    buffer.put("hostIdentifier", item.identifier);
    buffer.put("calendarTime", item.calendar_time);
    buffer.put("unixTime", item.time);
    buffer.put("severity", (google::LogSeverity)item.severity);
    buffer.put("filename", item.filename);
    buffer.put("line", item.line);
    buffer.put("message", item.message);
    buffer.put("version", kVersion);
    if (decorations.size() > 0) {
      buffer.put_child("decorations", dtree);
    }
    buffer.put("log_type", "status");

    // Convert to JSON, for storing a string-representation in the database.
    std::string json;
    try {
      std::stringstream json_output;
      pt::write_json(json_output, buffer, false);
      json = json_output.str();
    } catch (const pt::json_parser::json_parser_error& e) {
      // The log could not be represented as JSON.
      return Status(1, e.what());
    }

    _logStringInternal(
        (useSeparateStatusChannel_ ? status_channel_ : results_channel_), json, false);
  }

  return Status();
}

static void fallOnSword()
{
  LOG(WARNING) << "\n*******************************************************\n"
  "The number of cached log files has reached limit:"
  << FLAGS_cached_logger_max_files
  << "\nLogging will sent to /dev/null\n"
  "1. Fix connectivity issue with log forwarding.\n"
  "2. Delete some or all z_*.json files in DB directory\n"
  "*******************************************************";
}

/**
 * _enumerateExistingFiles is called from setProps()
 * to populate files_to_forward_ with any cached log
 * files in cache directory.
 */
void CachedLoggerPlugin::_enumerateExistingFiles() {
  auto dir = fs::path(cache_path_);
  std::vector<std::string> items;
  // Get list of all cached log files
  Status status = listFilesInDirectory((dir / LOGGER_CACHE_DIR).string(), items, false);
  // also add cached files in DB/ dir (legacy support)
  status = listFilesInDirectory(cache_path_, items, false);
  for (std::string filename : items) {
    // assume all our cached log files are in DB dir, prefixed with "z_"
    if (fs::path(filename).filename().string().find(CACHE_FILE_PREFIX) != 0) {
      continue;
    }
    // TODO: are these sorted?

    CacheFileInfo info(filename);

    // TODO: count lines and md5?

    files_to_forward_.push_back(info);
  }
  if (files_to_forward_.size() >= FLAGS_cached_logger_max_files) {
    fallOnSword();
    cacheLimitReached_ = true;
  }
}

/**
 * Resets counters, sets ts=now, updates filepath with timestamp.
 */
void CachedLoggerPlugin::_clearAndNameLog(LogChannel& channel, time_t now) {
  if (now == channel.ts) {
    // must be tons of results, if rotating in same second
    channel.subid++;
  } else {
    channel.subid = 0;
  }

  channel.num_bytes = 0;
  channel.num_lines = 0;
  channel.ts = now;

  // build name and path

  std::string suffix = "";
  if (channel.subid > 0) {
    suffix = "_" + std::to_string(channel.subid);
  }
  std::string name = channel.prefix + std::to_string(now) + suffix + ".json";
  auto path = fs::path(cache_path_) / LOGGER_CACHE_DIR / name;
  channel.filepath = path.make_preferred().string();
}

#define DIFF(NAME) { \
  diff.NAME = gStats.NAME - gStatsLast.NAME; \
s += std::string(#NAME) + ":" + std::to_string(diff.NAME) + " "; \
}

static void _reportStats(time_t now) {
  if (gLastStatTime == 0) {
    gLastStatTime = now;
    return;
  }

  if ((now - gLastStatTime) < STAT_REPORT_INTERVAL_SEC) {
    return;
  }

  std::string s = "period:" + std::to_string(now-gLastStatTime) + "s ";
  gLastStatTime = now;
  LoggerStats diff;

  DIFF(results_records_written);
  DIFF(results_records_sent);
  DIFF(results_files_written);
  DIFF(results_files_sent);
  DIFF(status_records_written);
  DIFF(status_records_sent);
  DIFF(status_files_written);
  DIFF(status_files_sent);
  DIFF(results_log_errors);
  DIFF(status_log_errors);
  DIFF(num_files_failed_to_send);

  if (FLAGS_cached_logger_stats) {
    LOG(WARNING) << s;
  }
}

/**
 * Does a fclose(channel.fp), adds channel.filepath to files_to_forward_[],
 * calls _clearAndNameLog(),
 * And does fopen(channel.filepath,"w"), and adds
 */
void CachedLoggerPlugin::_rotateLog(LogChannel& channel) {
  RecursiveLock lock(mutex_);

  // close existing
  if (!channel.filepath.empty() && channel.fp != nullptr) {
    CacheFileInfo info(channel.filepath, channel.num_lines);
    info.isResult = channel.isResult;
    // NOTE: 'status' counters will go to 'result' if !separate channel.
    // TODO: md5?
    files_to_forward_.push_back(info);
    fclose(channel.fp);
  }

  // no write if directory is not writable (see setProps)
  if (cache_path_.empty()) {
    channel.fp = nullptr;
    return;
  }

  time_t now = time(NULL);

  _reportStats(now);

  _clearAndNameLog(channel, now);

  if (files_to_forward_.size() >= FLAGS_cached_logger_max_files) {
    fallOnSword();
    cacheLimitReached_ = true;
  } else {
    cacheLimitReached_ = false;
  }

  channel.fp = FOPEN(channel.filepath.c_str(), "w");
  if (channel.fp == nullptr) {
    LOG(ERROR) << "unable to create log cache:" << channel.filepath;
  } else {
    if (channel.isResult) {
      gStats.results_files_written++;
    } else {
      gStats.status_files_written++;
    }
  }
}

static inline void updateSentStats(CacheFileInfo &info, bool wasSentSuccessfully){
  if (wasSentSuccessfully) {
    if (info.isResult) {
      gStats.results_files_sent ++;
      gStats.results_records_sent += info.num_lines;
    } else {
      gStats.status_files_sent++;
      gStats.status_records_sent += info.num_lines;
    }
  } else {
    gStats.num_files_failed_to_send ++;
  }
}

/*
 * When subclass has finished sending file, call this to delete it.
 * If (wasSentSuccessfully == false and
 *  FLAGS_cached_logger_keep_dead_letters == true)
 * then logs that failed to send will be written to ${DBDIR}/deadletter/
 * and will remain there for up to 7 days.
 */
void CachedLoggerPlugin::removeCachedFile(std::string& file_path,
                                          bool wasSentSuccessfully) {
  RecursiveLock lock(mutex_);
  VLOG(1) << "removeCachedFile " << file_path;

  // remove from list

  for (auto it = files_to_forward_.begin(); it != files_to_forward_.end();
       it++) {
    if (it->filepath == file_path) {
      updateSentStats(*it, wasSentSuccessfully);
      files_to_forward_.erase(it);
      break;
    }
  }
  // delete or move

  if (!wasSentSuccessfully) {
    LOG(ERROR) << "unable to send cached log file:" << file_path;

    // copy to dead_letter dir if !wasSentSuccessfully

    fs::path deadFile = (fs::path(cache_path_) / LOGGER_FAILED_DIR / fs::path(file_path).filename()).make_preferred();
    movePath(fs::path(file_path), deadFile);
  } else {
    if (FLAGS_cached_logger_audit_trail) {
      fs::path dest = (fs::path(cache_path_) / LOGGER_AUDIT_TRAIL_DIR / fs::path(file_path).filename()).make_preferred();
      movePath(fs::path(file_path), dest);
    } else {
      removePath(fs::path(file_path));
    }
  }
}

/*
 * Returns one or more log cache files waiting to be sent
 */
void CachedLoggerPlugin::getCachedFiles(
    std::vector<std::string>& cached_file_paths, int count) {
  RecursiveLock lock(mutex_);
  for (int i = 0; i < count && i < (int)files_to_forward_.size(); i++) {
    //VLOG(1) << i << "] getCachedFiles " << files_to_forward_[i].filepath;
    cached_file_paths.push_back(files_to_forward_[i].filepath);
  }
}

} // namespace osquery
