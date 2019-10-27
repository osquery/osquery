#pragma once

#include <osquery/plugins/logger.h>

namespace osquery {

/*
 * All files for this logger reside in database_path and are named
 * starting with CACHE_FILE_PREFIX.  Includes an 'S_' or 'R_',
 * depending on status or results files, includes the epoch timestamp
 * and logger name. e.g. 'z_R_aws_kinesis_1553117765.json'.
 *
 * The cache files are newline-delimited text-files.  Each line containing
 * one JSON status or result record.
 *
 * Each forwarder may have it's own limits on now many lines or records
 * and bytes it can handle.  The goal is to package each cache file
 * according to the LoggerBounds, so that it's ready for sending.
 */

#define CACHE_FILE_PREFIX "z_"

struct LoggerBounds {
  uint64_t max_records_per_batch;
  uint64_t max_bytes_per_record;
  uint64_t max_bytes_per_batch;
};

#define FORWARDER_STATUS_NO_CONNECTION 999
#define FORWARDER_STATUS_EMPTY_FILE 998
#define FORWARDER_STATUS_READ_ERROR 997

class Forwarder {
 public:
  /*
   * Even though CachedLoggerPlugin checks the bounds when files are
   * written, the bounds are supplied so send() can double-check them
   * if desired.
   */
  Forwarder(const LoggerBounds bounds) : bounds_(bounds) {}
  virtual ~Forwarder() {}

  /*
   * Seconds between checking for cached logs to send.
   */
  virtual uint32_t getIntervalSeconds() {
    return 10;
  }

  /*
   * Max number of files to send per interval.
   */
  virtual uint32_t getMaxFilesPerInterval() {
    return 2;
  }

  /*
   * If multiple files per interval, delay between each.
   */
  virtual uint32_t getBurstDelayMillis() {
    return 1500;
  }

  /*
   * Perform actual send.
   * Implementation is responsible for retries.
   * If unable to connect to server, return FORWARDER_STATUS_NO_CONNECTION.
   * The file will be deleted after return, unless
   *   status == FORWARDER_STATUS_NO_CONNECTION.
   */
  virtual Status send(std::string file_path) = 0;

 protected:
  const LoggerBounds bounds_;
};

// How long to wait before closing a file and adding to send queue
#define ROTATE_INTERVAL_SEC 25

struct LogChannel {
  FILE* fp;
  std::string filepath;
  time_t ts;
  uint32_t subid;

  uint64_t num_bytes;
  uint32_t num_lines;

  std::string prefix;
  std::string last_md5;
  bool isResult;
};

struct CacheFileInfo {
  std::string filepath;
  uint32_t num_lines;
  std::string md5;
  bool isResult;
  CacheFileInfo(std::string path, uint32_t num = 0, std::string filemd5 = "")
      : filepath(path), num_lines(num), md5(filemd5), isResult(false) {}
};

/**
 * This logger writes result and status into newline-delimited text files.
 * Cached Format:
 *  - Every line beginning with a '{' is a JSON object
 *  - Lines beginning with '#' include metadata, and should be ignored by
 *    forwarder or application ingesting logs.
 * This is designed to be subclassed, and used in conjunction with a forwarder.
 * Subclass can call configure() to set the cache file parameters specific
 * to the transport.  For example, aws kinesis has 1000 records per second
 * limit, and record size of 1MB.
 *
 * The subclasses of CachedLoggerPlugin should call start() from setUp() with
 * an instance of the Forwarder.  The start() method will create a
 * dispatcher thread and call Forwarder.send() at the desired interval.
 *
 */
class CachedLoggerPlugin : public LoggerPlugin {
 public:
  /**
   * Call this first from from setUp() of any inherited classes.
   * If useSeparateStatusChannel == true, status log entries will be
   * cached and sent separately from results.
   */
  void setProps(std::string logname,
                bool useSeparateStatusChannel,
                const LoggerBounds bounds);

  /**
   * Call this at end of setUp() in any inherited classes.
   */
  void start(std::shared_ptr<Forwarder> spForwarder,
             uint32_t interval_seconds,
             uint32_t burst_file_count,
             uint32_t burst_sleep_millis);

  /*
   * Returns one or more log cache files waiting to be sent.
   * Called internally by ForwarderThread.  Consider this private.
   */
  void getCachedFiles(std::vector<std::string>& cached_file_paths, int count);

  /*
   * Called internally by ForwarderThread.  Consider this private.
   */
  void removeCachedFile(std::string& file_path, bool wasSentSuccessfully);

  // override standard logger entrypoints ... writes to cached text files

  Status logString(const std::string& s) override;

  Status logStatus(const std::vector<StatusLogLine>& log) override;

  /**
   * Internally, this just calls logString() for each.
   */
  // Status logStringBatch(std::vector<std::string>& items) override;

  /**
   * important : override tearDown so forwarderThread_ can be interrupted.
   * Otherwise, agent may not exit.  Also closes channel file handles.
   */
  void tearDown() override;

  /**
   * @returns true if the channel file should be closed, and a new file started.
   * Considers:
   *   - channel.num_bytes + line_length > bounds.max_bytes_per_batch
   *   - channel.num_lines + 1 > bounds.max_records_per_batch
   *   - (now - channel.ts > ROTATE_INTERVAL_SEC) and num_files_queued < 6
   * This function should be treated as private. (static + public for unit test)
   */
  static bool _needsRotate(LoggerBounds bounds,
                           LogChannel& channel,
                           time_t now,
                           size_t line_length,
                           size_t num_files_queued);

 protected:
  /**
   * _logStringInternal() is used by logString() and logStatus().
   * It holds the mutex, checks bounds, does _rotateLog if needed,
   * increments channel counters, and writes to file.
   */
  Status _logStringInternal(LogChannel& channel,
                            const std::string& s,
                            bool isResult);

  /**
   * _enumerateExistingFiles is called from setProps()
   * to populate files_to_forward_ with any cached log
   * files in cache directory.
   */
  void _enumerateExistingFiles();

  /**
   * Does a fclose(channel.fp), adds channel.filepath to files_to_forward_[],
   * calls _clearAndNameLog(),
   * And does fopen(channel.filepath,"w"), and adds
   */
  void _rotateLog(LogChannel& channel);

  /**
   * Resets counters, sets ts=now, updates filepath with timestamp.
   */
  void _clearAndNameLog(LogChannel& channel, time_t now);

  bool useSeparateStatusChannel_;
  LoggerBounds bounds_;
  std::shared_ptr<InternalRunnable> forwarderThread_;
  std::string cache_path_;
  LogChannel results_channel_;
  LogChannel status_channel_;
  std::vector<CacheFileInfo> files_to_forward_;
  bool cacheLimitReached_{false};
};

#ifdef WIN32
inline FILE* FOPEN(const char* FILEPATH, const char* MODE) {
  FILE* fp;
  if (0 != fopen_s(&fp, FILEPATH, MODE)) {
    return nullptr;
  }
  return fp;
}
#else
#define FOPEN(FILEPATH, MODE) fopen(FILEPATH, MODE)
#endif

} // namespace osquery
