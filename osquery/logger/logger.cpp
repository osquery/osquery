/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#ifdef WIN32
#include "osquery/logger/plugins/windows_event_log.h"
#else
#include <syslog.h>
#endif

#include <algorithm>
#include <future>
#include <queue>
#include <thread>

#include <boost/noncopyable.hpp>

#include <osquery/database.h>
#include <osquery/events.h>
#include <osquery/extensions.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

namespace pt = boost::property_tree;
namespace rj = rapidjson;

namespace osquery {

FLAG(bool, verbose, false, "Enable verbose informational messages");
FLAG_ALIAS(bool, verbose_debug, verbose);
FLAG_ALIAS(bool, debug, verbose);

/// Despite being a configurable option, this is only read/used at load.
FLAG(bool, disable_logging, false, "Disable ERROR/INFO logging");

FLAG(string, logger_plugin, "filesystem", "Logger plugin name");

/// Log each added or removed line individually, as an "event".
FLAG(bool, logger_event_type, true, "Log scheduled results as events");
FLAG_ALIAS(bool, log_result_events, logger_event_type);

/// Log each row from a snapshot query individually, as an "event".
FLAG(bool,
     logger_snapshot_event_type,
     false,
     "Log scheduled snapshot results as events");

/// Alias for the minloglevel used internally by GLOG.
FLAG(int32, logger_min_status, 0, "Minimum level for status log recording");

FLAG(bool,
     logger_secondary_status_only,
     false,
     "Only send status logs to secondary logger plugins");

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

/**
 * @brief Logger plugin registry.
 *
 * This creates an osquery registry for "logger" which may implement
 * LoggerPlugin. Only strings are logged in practice, and LoggerPlugin provides
 * a helper member for transforming PluginRequest%s to strings.
 */
CREATE_REGISTRY(LoggerPlugin, "logger");

class LoggerDisabler;

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

  /// Pop from the aync sender queue and wait for one send to complete.
  void WaitTillSent() override;

 public:
  /// Accessor/mutator to dump all of the buffered logs.
  std::vector<StatusLogLine>& dump();

  /// Remove the buffered log sink from Glog.
  void disable();

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

  /**
   * @brief Check if a given logger plugin was the first or 'primary'.
   *
   * Within the osquery core the BufferedLogSink acts as a router for status
   * logs. While initializing it inspects the set of logger plugins and saves
   * the first as the 'primary'.
   *
   * Checks within the core may act on this state. Checks within extensions
   * cannot, and thus any check for primary logger plugins is true.
   * While this is a limitation, in practice if a remote logger plugin is called
   * it is intended to receive all logging data.
   *
   * @param plugin Check if this target plugin is primary.
   * @return true of the provided plugin was the first specified.
   */
  bool isPrimaryLogger(const std::string& plugin) const;

  /// Set the primary logger plugin is none has been previously specified.
  void setPrimary(const std::string& plugin);

 public:
  /// Queue of sender functions that relay status logs to all plugins.
  std::queue<std::future<void>> senders;

 public:
  BufferedLogSink(BufferedLogSink const&) = delete;
  void operator=(BufferedLogSink const&) = delete;

 private:
  /// Create the log sink as buffering or forwarding.
  BufferedLogSink() = default;

  /// Remove the log sink.
  ~BufferedLogSink();

 private:
  /// Intermediate log storage until an osquery logger is initialized.
  std::vector<StatusLogLine> logs_;

  /**
   * @Brief Is the logger temporarily disabled.
   *
   * This is an atomic because the friend class LoggerDisabler will toggle the
   * enabled/disabled flag and call enable()/disable().
   *
   * The Google Log Sink will still be active, but the send method also checks
   * enabled and drops log lines to the flood if the forwarder is not enabled.
   */
  std::atomic<bool> enabled_{false};

  /// Boolean to help the logger disabler, no need to take action if not active.
  bool active_{false};

  /// Track multiple loggers that should receive sinks from the send forwarder.
  std::vector<std::string> sinks_;

  /// Keep track of the first, or 'primary' logger.
  std::string primary_;

  /// Mutex for checking primary status.
  mutable Mutex primary_mutex_;

  /// Mutex protecting activation and enabling of the buffered status logger.
  Mutex enable_mutex_;

 private:
  friend class LoggerDisabler;
};

/// Mutex protecting accesses to buffered status logs.
Mutex kBufferedLogSinkLogs;

/// Mutex protecting queued status log futures.
Mutex kBufferedLogSinkSenders;

/// Scoped helper to perform logging actions without races.
class LoggerDisabler : private boost::noncopyable {
 public:
  LoggerDisabler();
  ~LoggerDisabler();

 private:
  /// Value of the 'logtostderr' Glog status when constructed.
  bool stderr_status_;

  /// Value of the BufferedLogSink's enabled status when constructed.
  bool enabled_;
};

LoggerDisabler::LoggerDisabler()
    : stderr_status_(FLAGS_logtostderr),
      enabled_(BufferedLogSink::get().enabled_) {
  BufferedLogSink::get().disable();
  FLAGS_logtostderr = true;
}

LoggerDisabler::~LoggerDisabler() {
  // Only enable if the sink was enabled when the disabler was requested.
  if (enabled_) {
    BufferedLogSink::get().enable();
  }
  FLAGS_logtostderr = stderr_status_;
}

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

static void deserializeIntermediateLog(const PluginRequest& request,
                                       std::vector<StatusLogLine>& log) {
  if (request.count("log") == 0) {
    return;
  }

  rj::Document doc;
  if (doc.Parse(request.at("log").c_str()).HasParseError()) {
    return;
  }

  for (auto& line : doc.GetArray()) {
    log.push_back({
        static_cast<StatusLogSeverity>(line["s"].GetInt()),
        line["f"].GetString(),
        line["i"].GetUint64(),
        line["m"].GetString(),
        line["c"].GetString(),
        line["u"].GetUint64(),
        line["h"].GetString(),
    });
  }
}

inline bool logStderrOnly() {
  // Do not write logfiles if filesystem is not included as a plugin.
  if (Registry::get().external()) {
    return true;
  }
  return Flag::getValue("logger_plugin").find("filesystem") ==
         std::string::npos;
}

void setVerboseLevel() {
  auto default_level = google::GLOG_INFO;
  if (Initializer::isShell()) {
    // Do log only WARNING, ERROR to log sinks.
    default_level = google::GLOG_WARNING;
  }

  if (Flag::getValue("verbose") == "true") {
    // Turn verbosity up to 1.
    // Do log DEBUG, INFO, WARNING, ERROR to their log files.
    // Do log the above and verbose=1 to stderr (can be turned off later).
    FLAGS_minloglevel = google::GLOG_INFO;
    FLAGS_alsologtostderr = true;
    FLAGS_v = 1;
  } else {
    if (!Flag::isDefault("logger_min_status")) {
      auto i = Flag::getInt32Value("logger_min_status");
      FLAGS_minloglevel = static_cast<decltype(FLAGS_minloglevel)>(i);
    } else if (Flag::isDefault("minloglevel")) {
      FLAGS_minloglevel = default_level;
    }

    if (!Flag::isDefault("logger_min_stderr")) {
      auto i = Flag::getInt32Value("logger_min_stderr");
      FLAGS_stderrthreshold = static_cast<decltype(FLAGS_logger_min_stderr)>(i);
    } else if (Flag::isDefault("stderrthreshold")) {
      FLAGS_stderrthreshold = default_level;
    }
  }

  if (!FLAGS_logger_stderr) {
    FLAGS_logtostderr = false;
    FLAGS_alsologtostderr = false;
  }

  if (logStderrOnly()) {
    FLAGS_logtostderr = true;
  }

  if (FLAGS_disable_logging) {
    FLAGS_logtostderr = true;
  }
}

void initStatusLogger(const std::string& name, bool init_glog) {
#ifndef FBTHRIFT
  // No color available when using fbthrift.
  FLAGS_colorlogtostderr = true;
#endif
  FLAGS_logbufsecs = 0;
  FLAGS_stop_logging_if_full_disk = true;
  // The max size for individual log file is 10MB.
  FLAGS_max_log_size = 10;

  setVerboseLevel();
  // Start the logging, and announce the daemon is starting.
  if (init_glog) {
    google::InitGoogleLogging(name.c_str());
  }
  BufferedLogSink::get().setUp();
}

void initLogger(const std::string& name) {
  // Check if logging is disabled, if so then no need to shuttle intermediates.
  if (FLAGS_disable_logging) {
    return;
  }

  // Stop the buffering sink and store the intermediate logs.
  BufferedLogSink::get().disable();
  BufferedLogSink::get().resetPlugins();

  bool forward = false;
  PluginRequest init_request = {{"init", name}};
  PluginRequest features_request = {{"action", "features"}};
  auto logger_plugin = RegistryFactory::get().getActive("logger");
  // Allow multiple loggers, make sure each is accessible.
  for (const auto& logger : osquery::split(logger_plugin, ",")) {
    BufferedLogSink::get().setPrimary(logger);
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
    relayStatusLogs(true);
  }
}

BufferedLogSink& BufferedLogSink::get() {
  static BufferedLogSink sink;
  return sink;
}

void BufferedLogSink::setUp() {
  WriteLock lock(enable_mutex_);

  if (!active_) {
    active_ = true;
    google::AddLogSink(&get());
  }
}

void BufferedLogSink::disable() {
  WriteLock lock(enable_mutex_);

  if (enabled_) {
    enabled_ = false;
    if (active_) {
      active_ = false;
      google::RemoveLogSink(&get());
    }
  }
}

void BufferedLogSink::enable() {
  WriteLock lock(enable_mutex_);

  if (!enabled_) {
    enabled_ = true;
    if (!active_) {
      active_ = true;
      google::AddLogSink(&get());
    }
  }
}

void BufferedLogSink::send(google::LogSeverity severity,
                           const char* full_filename,
                           const char* base_filename,
                           int line,
                           const struct ::tm* tm_time,
                           const char* message,
                           size_t message_len) {
  if (FLAGS_disable_logging) {
    return;
  }

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
  if (enabled_ && !Initializer::isDaemon()) {
    relayStatusLogs(FLAGS_logger_status_sync);
  }
}

void BufferedLogSink::WaitTillSent() {
  std::future<void> first;

  {
    WriteLock lock(kBufferedLogSinkSenders);
    if (senders.empty()) {
      return;
    }
    first = std::move(senders.back());
    senders.pop();
  }

  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    first.wait();
  } else {
    // Windows is locking by scheduling an async on the main thread.
    first.wait_for(std::chrono::microseconds(100));
  }
}

void BufferedLogSink::setPrimary(const std::string& plugin) {
  WriteLock lock(primary_mutex_);
  if (primary_.empty()) {
    primary_ = plugin;
  }
}

std::vector<StatusLogLine>& BufferedLogSink::dump() {
  return logs_;
}

bool BufferedLogSink::isPrimaryLogger(const std::string& plugin) const {
  WriteLock lock(primary_mutex_);
  return (primary_.empty() || plugin == primary_);
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
  disable();
}

Status LoggerPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  QueryLogItem item;
  std::vector<StatusLogLine> intermediate_logs;
  if (request.count("string") > 0) {
    return this->logString(request.at("string"));
  } else if (request.count("snapshot") > 0) {
    return this->logSnapshot(request.at("snapshot"));
  } else if (request.count("init") > 0) {
    deserializeIntermediateLog(request, intermediate_logs);
    this->setProcessName(request.at("init"));
    this->init(this->name(), intermediate_logs);
    return Status(0);
  } else if (request.count("status") > 0) {
    deserializeIntermediateLog(request, intermediate_logs);
    return this->logStatus(intermediate_logs);
  } else if (request.count("event") > 0) {
    return this->logEvent(request.at("event"));
  } else if (request.count("action") && request.at("action") == "features") {
    size_t features = 0;
    features |= (usesLogStatus()) ? LOGGER_FEATURE_LOGSTATUS : 0;
    features |= (usesLogEvent()) ? LOGGER_FEATURE_LOGEVENT : 0;
    return Status(static_cast<int>(features));
  } else {
    return Status(1, "Unsupported call to logger plugin");
  }
}

Status logString(const std::string& message, const std::string& category) {
  return logString(
      message, category, RegistryFactory::get().getActive("logger"));
}

Status logString(const std::string& message,
                 const std::string& category,
                 const std::string& receiver) {
  if (FLAGS_disable_logging) {
    return Status(0, "Logging disabled");
  }

  Status status;
  for (const auto& logger : osquery::split(receiver, ",")) {
    if (FLAGS_logger_secondary_status_only &&
        !BufferedLogSink::get().isPrimaryLogger(logger)) {
      continue;
    }

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

Status logQueryLogItem(const QueryLogItem& results) {
  return logQueryLogItem(results, RegistryFactory::get().getActive("logger"));
}

Status logQueryLogItem(const QueryLogItem& results,
                       const std::string& receiver) {
  if (FLAGS_disable_logging) {
    return Status(0, "Logging disabled");
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
    return Status(0, "Logging disabled");
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
      if (FLAGS_logger_secondary_status_only &&
          !BufferedLogSink::get().isPrimaryLogger(logger)) {
        continue;
      }

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

size_t queuedSenders() {
  ReadLock lock(kBufferedLogSinkSenders);
  return BufferedLogSink::get().senders.size();
}

void relayStatusLogs(bool async) {
  if (FLAGS_disable_logging || !DatabasePlugin::kDBInitialized) {
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

  if (async) {
    sender();
  } else {
    std::packaged_task<void()> task(std::move(sender));
    auto result = task.get_future();
    std::thread(std::move(task)).detach();

    // Lock accesses to the sender queue.
    WriteLock lock(kBufferedLogSinkSenders);
    BufferedLogSink::get().senders.push(std::move(result));
  }
}

void systemLog(const std::string& line) {
#ifndef WIN32
  syslog(LOG_NOTICE, "%s", line.c_str());
#endif
}
}
