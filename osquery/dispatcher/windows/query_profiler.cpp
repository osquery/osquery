#include <osquery/dispatcher/query_profiler.h>

namespace osquery {
void launchQueryWithProfiling(const std::string& name,
                              std::function<Status()> launchQuery) {
  const auto start_time_point = std::chrono::steady_clock::now();
  const auto status = launchQuery();
  const auto monitoring_path_prefix =
      (boost::format("scheduler.executing_query.%s.%s") % name %
       (status.ok() ? "success" : "failure"))
          .str();
  const auto query_duration =
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now() - start_time_point);
  if (Killswitch::get().isExecutingQueryMonitorEnabled()) {
    monitoring::record(monitoring_path_prefix + ".time.real.milis",
                       query_duration.count(),
                       monitoring::PreAggregationType::Min);
  }
}
} // namespace osquery
