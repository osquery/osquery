/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifndef WIN32
#include <syslog.h>
#endif

#include <algorithm>
#include <future>
#include <optional>
#include <queue>
#include <thread>

#include <boost/noncopyable.hpp>

#include <osquery/core/flags.h>
#include <osquery/core/plugins/logger.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/events/eventfactory.h>
#include <osquery/extensions/extensions.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/data_logger.h>
#include <osquery/numeric_monitoring/numeric_monitoring.h>
#include <osquery/registry/registry_factory.h>

#include <osquery/core/flagalias.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>

namespace rj = rapidjson;

namespace osquery {

FLAG(bool, verbose, false, "Enable verbose informational messages");

/// Despite being a configurable option, this is only read/used at load.
FLAG(bool, disable_logging, false, "Disable ERROR/INFO logging");

CLI_FLAG(string, logger_plugin, "filesystem", "Logger plugin name");

/// Log each added or removed line individually, as an "event".
FLAG(bool, logger_event_type, true, "Log scheduled results as events");

/// Log each row from a snapshot query individually, as an "event".
FLAG(bool,
     logger_snapshot_event_type,
     false,
     "Log scheduled snapshot results as events");

/// Alias for the minloglevel used internally by GLOG.
FLAG(int32, logger_min_status, 0, "Minimum level for status log recording");

/// Alias for the stderrthreshold used internally by GLOG.
FLAG(int32,
     logger_min_stderr,
     0,
     "Minimum level for statuses written to stderr");

/// It is difficult to set logging to stderr on/off at runtime.
CLI_FLAG(bool, logger_stderr, true, "Write status logs to stderr");

/**
 * @brief This hidden flag is for testing status logging.
 *
 * When enabled, logs are pushed directly to logger plugin from Glog.
 * Otherwise they are buffered and an async request for draining is sent
 * for each log.
 *
 * Within the daemon, logs are drained every 3 seconds.
 */
HIDDEN_FLAG(bool,
            logger_status_sync,
            false,
            "Always send status logs synchronously");

DECLARE_bool(enable_numeric_monitoring);

/**
 * @brief Logger plugin registry.
 *
 * This creates an osquery registry for "logger" which may implement
 * LoggerPlugin. Only strings are logged in practice, and LoggerPlugin provides
 * a helper member for transforming PluginRequest%s to strings.
 */
CREATE_REGISTRY(LoggerPlugin, "logger");

/**
 * @brief A custom Glog log sink for forwarding or buffering status logs.
 *
 * This log sink has two modes, it can buffer Glog status logs until an osquery
 * logger is initialized or forward Glog status logs to an initialized and
 * appropriate logger. The appropriateness is determined by the logger when its
 * LoggerPlugin::init method is called. If the `init` method returns success
 * then a BufferedLogSink will start forwarding status logs to
 * LoggerPlugin::logStatus.
 *
 * This facility will start buffering when first used and stop buffering
 * (aka remove itself as a Glog sink) using the exposed APIs. It will live
 * throughout the life of the process for two reasons: (1) It makes sense when
 * the active logger plugin is handling Glog status logs and (2) it must remove
 * itself as a Glog target.
 */
class BufferedLogSink : public google::LogSink, private boost::noncopyable {
 public:
  /// We create this as a Singleton for proper disable/shutdown.
  static BufferedLogSink& get();

  /// The Glog-API LogSink call-in method.
  void send(google::LogSeverity severity,
            const char* full_filename,
            const char* base_filename,
            int line,
            const struct ::tm* tm_time,
            const char* message,
            size_t message_len) override;

  /// Pop from the async sender queue and wait for one send to complete.
  void WaitTillSent() override;

 public:
  /// Accessor/mutator to dump all of the buffered logs.
  std::vector<StatusLogLine>& dump();

  /// Add the buffered log sink to Glog.
  void enable();

  /// Start the Buffered Sink, without enabling forwarding to loggers.
  void setUp();

  /**
   * @brief Add a logger plugin that should receive status updates.
   *
   * Since the logger may support multiple active logger plugins the sink
   * will keep track of those plugins that returned success after ::init.
   * This list of plugins will received forwarded messages from the sink.
   *
   * This list is important because sending logs to plugins that also use
   * and active Glog Sink (supports multiple) will create a logging loop.
   */
  void addPlugin(const std::string& name);

  /// Clear the sinks list, clear the named plugins added by addPlugin.s
  void resetPlugins();

  /// Retrieve the list of enabled plugins that should have logs forwarded.
  const std::vector<std::string>& enabledPlugins() const;

 public:
  BufferedLogSink(BufferedLogSink const&) = delete;
  void operator=(BufferedLogSink const&) = delete;

 private:
  /// Create the log sink as buffering or forwarding.
  BufferedLogSink() = default;

  /// Stop the log sink.
  ~BufferedLogSink();

 private:
  /// Intermediate log storage until an osquery logger is initialized.
  std::vector<StatusLogLine> logs_;

  /**
   * @Brief Is the logger temporarily disabled.
   *
   * The Google Log Sink will still be active, but the send method also checks
   * enabled and drops log lines to the flood if the forwarder is not enabled.
   */
  std::atomic<bool> enabled_{false};

  /// Track multiple loggers that should receive sinks from the send forwarder.
  std::vector<std::string> sinks_;
};

/// Mutex protecting accesses to buffered status logs.
Mutex kBufferedLogSinkLogs;

/// Used to wait on the thread that defers relaying the buffered status logs
thread_local std::optional<std::future<void>> kOptBufferedLogSinkSender;

static void serializeIntermediateLog(const std::vector<StatusLogLine>& log,
                                     PluginRequest& request) {
  auto doc = JSON::newArray();
  for (const auto& i : log) {
    auto line = doc.getObject();
    doc.add("s", static_cast<int>(i.severity), line);
    doc.addRef("f", i.filename, line);
    doc.add("i", i.line, line);
    doc.addRef("m", i.message, line);
    doc.addRef("h", i.identifier, line);
    doc.addRef("c", i.calendar_time, line);
    doc.add("u", i.time, line);
    doc.push(line);
  }

  doc.toString(request["log"]);
}

void setVerboseLevel() {
#ifdef OSQUERY_IS_FUZZING
  return;
#endif

  if (Flag::getValue("verbose") == "true") {
    // Turn verbosity up to 1.
    // Do log DEBUG, INFO, WARNING, ERROR to their log files.
    // Do log the above and verbose=1 to stderr (can be turned off later).
    FLAGS_minloglevel = google::GLOG_INFO;
    FLAGS_alsologtostderr = true;
    FLAGS_v = 1;
  } else {
    /* We use a different default for the log level if running as a daemon or if
     * running as a shell. If the flag was set we just use that in both cases.
     */
    if (Flag::isDefault("logger_min_status") && isShell()) {
      FLAGS_minloglevel = google::GLOG_WARNING;
    } else {
      FLAGS_minloglevel = Flag::getInt32Value("logger_min_status");
    }
    FLAGS_stderrthreshold = Flag::getInt32Value("logger_min_stderr");
  }

  if (!FLAGS_logger_stderr) {
    FLAGS_stderrthreshold = 3;
    FLAGS_alsologtostderr = false;
  }

  FLAGS_logtostderr = true;
}

void initStatusLogger(const std::string& name, bool init_glog) {
  FLAGS_logbufsecs = 0;
  FLAGS_stop_logging_if_full_disk = true;
  // The max size for individual log file is 10MB.
  FLAGS_max_log_size = 10;

  // Begin with only logging to stderr.
  FLAGS_logtostderr = true;
  FLAGS_stderrthreshold = 3;

  setVerboseLevel();
  // Start the logging, and announce the daemon is starting.
  if (init_glog) {
    google::InitGoogleLogging(name.c_str(), &googleLogCustomPrefix);
  }

  if (!FLAGS_disable_logging) {
    BufferedLogSink::get().setUp();
  }
}

void initLogger(const std::string& name) {
  BufferedLogSink::get().resetPlugins();

  bool forward = false;
  PluginRequest init_request = {{"init", name}};
  PluginRequest features_request = {{"action", "features"}};
  auto logger_plugin = RegistryFactory::get().getActive("logger");
  // Allow multiple loggers, make sure each is accessible.
  for (const auto& logger : osquery::split(logger_plugin, ",")) {
    if (!RegistryFactory::get().exists("logger", logger)) {
      continue;
    }

    Registry::call("logger", logger, init_request);
    auto status = Registry::call("logger", logger, features_request);
    if ((status.getCode() & LOGGER_FEATURE_LOGSTATUS) > 0) {
      // Glog status logs are forwarded to logStatus.
      forward = true;
      // To support multiple plugins we only add the names of plugins that
      // return a success status after initialization.
      BufferedLogSink::get().addPlugin(logger);
    }

    if ((status.getCode() & LOGGER_FEATURE_LOGEVENT) > 0) {
      EventFactory::addForwarder(logger);
    }
  }

  if (forward) {
    // Begin forwarding after all plugins have been set up.
    BufferedLogSink::get().enable();
    relayStatusLogs(LoggerRelayMode::Sync);
  }
}

BufferedLogSink& BufferedLogSink::get() {
  static BufferedLogSink sink;
  return sink;
}

void BufferedLogSink::setUp() {
  google::AddLogSink(&get());
}

void BufferedLogSink::enable() {
  enabled_ = true;
}

void BufferedLogSink::send(google::LogSeverity severity,
                           const char* full_filename,
                           const char* base_filename,
                           int line,
                           const struct ::tm* tm_time,
                           const char* message,
                           size_t message_len) {
  // WARNING, be extremely careful when accessing data here.
  // This should not cause any persistent storage or logging actions.
  {
    WriteLock lock(kBufferedLogSinkLogs);
    logs_.push_back({(StatusLogSeverity)severity,
                     std::string(base_filename),
                     static_cast<size_t>(line),
                     std::string(message, message_len),
                     toAsciiTimeUTC(tm_time),
                     toUnixTime(tm_time),
                     std::string()});
  }

  // The daemon will relay according to the schedule.
  if (enabled_ && !isDaemon()) {
    relayStatusLogs(FLAGS_logger_status_sync ? LoggerRelayMode::Sync
                                             : LoggerRelayMode::Async);
  }
}

void BufferedLogSink::WaitTillSent() {
  if (kOptBufferedLogSinkSender.has_value()) {
    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      kOptBufferedLogSinkSender->wait();
    } else {
      /* We cannot wait indefinitely because glog doesn't use read/write locks
        on Windows. When we are in a recursive logging situation, there's a
        thread that is waiting here for a new thread it launched to finish its
        logging, and it does so while holding an exclusive lock inside glog
        (sink_mutex_), instead of in read mode only. The new thread needs to be
        able to acquire the same lock to log the message though,
        so unless this thread yields, we end up in a deadlock. */
      kOptBufferedLogSinkSender->wait_for(std::chrono::microseconds(100));
    }
    kOptBufferedLogSinkSender.reset();
  }
}

std::vector<StatusLogLine>& BufferedLogSink::dump() {
  return logs_;
}

void BufferedLogSink::addPlugin(const std::string& name) {
  sinks_.push_back(name);
}

void BufferedLogSink::resetPlugins() {
  sinks_.clear();
}

const std::vector<std::string>& BufferedLogSink::enabledPlugins() const {
  return sinks_;
}

BufferedLogSink::~BufferedLogSink() {
  enabled_ = false;
}

Status logString(const std::string& message, const std::string& category) {
  return logString(
      message, category, RegistryFactory::get().getActive("logger"));
}

Status logString(const std::string& message,
                 const std::string& category,
                 const std::string& receiver) {
  if (FLAGS_disable_logging) {
    return Status::success();
  }

  Status status;
  for (const auto& logger : osquery::split(receiver, ",")) {
    if (Registry::get().exists("logger", logger, true)) {
      auto plugin = Registry::get().plugin("logger", logger);
      auto logger_plugin = std::dynamic_pointer_cast<LoggerPlugin>(plugin);
      status = logger_plugin->logString(message);
    } else {
      status = Registry::call(
          "logger", logger, {{"string", message}, {"category", category}});
    }
  }
  return status;
}

namespace {
const std::string kTotalQueryCounterMonitorPath("query.total.count");
}

Status logQueryLogItem(const QueryLogItem& results) {
  return logQueryLogItem(results, RegistryFactory::get().getActive("logger"));
}

Status logQueryLogItem(const QueryLogItem& results,
                       const std::string& receiver) {
  if (FLAGS_disable_logging) {
    return Status::success();
  }

  if (FLAGS_enable_numeric_monitoring) {
    monitoring::record(
        kTotalQueryCounterMonitorPath, 1, monitoring::PreAggregationType::Sum);
  }

  std::vector<std::string> json_items;
  Status status;
  if (FLAGS_logger_event_type) {
    status = serializeQueryLogItemAsEventsJSON(results, json_items);
  } else {
    std::string json;
    status = serializeQueryLogItemJSON(results, json);
    json_items.emplace_back(json);
  }
  if (!status.ok()) {
    return status;
  }

  for (const auto& json : json_items) {
    status = logString(json, "event", receiver);
  }
  return status;
}

Status logSnapshotQuery(const QueryLogItem& item) {
  if (FLAGS_disable_logging) {
    return Status::success();
  }

  if (FLAGS_enable_numeric_monitoring) {
    monitoring::record(
        kTotalQueryCounterMonitorPath, 1, monitoring::PreAggregationType::Sum);
  }

  std::vector<std::string> json_items;
  Status status;
  if (FLAGS_logger_snapshot_event_type) {
    status = serializeQueryLogItemAsEventsJSON(item, json_items);
  } else {
    std::string json;
    status = serializeQueryLogItemJSON(item, json);
    json_items.emplace_back(json);
  }
  if (!status.ok()) {
    return status;
  }

  for (const auto& json : json_items) {
    auto receiver = RegistryFactory::get().getActive("logger");
    for (const auto& logger : osquery::split(receiver, ",")) {
      if (Registry::get().exists("logger", logger, true)) {
        auto plugin = Registry::get().plugin("logger", logger);
        auto logger_plugin = std::dynamic_pointer_cast<LoggerPlugin>(plugin);
        status = logger_plugin->logSnapshot(json);
      } else {
        status = Registry::call("logger", logger, {{"snapshot", json}});
      }
    }
  }

  return status;
}

size_t queuedStatuses() {
  ReadLock lock(kBufferedLogSinkLogs);
  return BufferedLogSink::get().dump().size();
}

void relayStatusLogs(LoggerRelayMode relay_mode) {
  if (FLAGS_disable_logging || !databaseInitialized()) {
    // The logger plugins may not be setUp if logging is disabled.
    // If the database is not setUp, or is in a reset, status logs continue
    // to buffer.
    return;
  }

  {
    ReadLock lock(kBufferedLogSinkLogs);
    if (BufferedLogSink::get().dump().size() == 0) {
      return;
    }
  }

  auto sender = ([]() {
    auto identifier = getHostIdentifier();

    // Construct a status log plugin request.
    PluginRequest request = {{"status", "true"}};
    {
      WriteLock lock(kBufferedLogSinkLogs);
      auto& status_logs = BufferedLogSink::get().dump();

      // Prevent serializing and broadcasting an empty response
      if (status_logs.empty()) {
        return;
      }

      for (auto& log : status_logs) {
        // Copy the host identifier into each status log.
        log.identifier = identifier;
      }

      serializeIntermediateLog(status_logs, request);

      // Flush the buffered status logs.
      status_logs.clear();
    }

    auto logger_plugin = RegistryFactory::get().getActive("logger");
    for (const auto& logger : osquery::split(logger_plugin, ",")) {
      auto& enabled = BufferedLogSink::get().enabledPlugins();
      if (std::find(enabled.begin(), enabled.end(), logger) != enabled.end()) {
        // Skip the registry's logic, and send directly to the core's logger.
        PluginResponse response;
        Registry::call("logger", logger, request, response);
      }
    }
  });

  if (relay_mode == LoggerRelayMode::Sync) {
    sender();
  } else {
    std::packaged_task<void()> task(std::move(sender));
    kOptBufferedLogSinkSender = task.get_future();
    std::thread(std::move(task)).detach();
  }
}

void systemLog(const std::string& line) {
#ifndef WIN32
  syslog(LOG_NOTICE, "%s", line.c_str());
#endif
}

void googleLogCustomPrefix(std::ostream& s,
                           const LogMessageInfo& l,
                           void* data) {
  s << l.severity[0] << std::setw(2) << (l.time.month() + 1) << std::setw(2)
    << l.time.day() << ' ' << std::setw(2) << l.time.hour() << ':'
    << std::setw(2) << l.time.min() << ':' << std::setw(2) << l.time.sec()
    << '.' << std::setw(6) << l.time.usec() << ' ' << std::setfill(' ')
    << std::setw(5) << l.thread_id << std::setfill('0') << ' ' << l.filename
    << ':' << l.line_number << ']';
}
} // namespace osquery
