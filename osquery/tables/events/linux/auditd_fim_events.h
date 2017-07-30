#pragma once

#include "osquery/events/linux/auditdfim.h"

#include <osquery/events.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace osquery {
/// This structure stores the information for a tracked file handle
struct HandleInformation final {
  /// Operation type affecting this file handle
  enum class OperationType { Open, Read, Write };

  /// The last operation executed on this file handle; this is used by the
  /// filtering logic to reduce output
  OperationType last_operation{OperationType::Open};

  /// The path for this file handle
  std::string path;
};

/// Holds the file descriptor map for a process
using AuditdFimHandleMap = std::unordered_map<int, HandleInformation>;

/// Holds the file descriptor maps for all processes
using AuditdFimProcessMap = std::unordered_map<__pid_t, AuditdFimHandleMap>;

/// A simple vector of strings
using StringList = std::vector<std::string>;

/// Contains the AuditdFim configuration
struct AuditdFimConfiguration final {
  StringList included_path_list;
  StringList excluded_path_list;
  bool show_accesses{true};
};

/// This subscriber receives syscall events from the publisher and
/// builds a file descriptor map for each process. Once a read or
/// write operation is performed, a new row is emitted (according
/// to how it has been configured).
class AuditdFimEventSubscriber final
    : public EventSubscriber<AuditdFimEventPublisher> {
  AuditdFimProcessMap process_map_;
  AuditdFimConfiguration configuration_;

 public:
  Status setUp() override;
  Status init() override;

  /// Applies the user configuration to the subscriber
  void configure() override;

  /// This callback is called once for each AuditdFimEventPublisher::fire()
  Status Callback(const ECRef& event_context,
                  const SCRef& subscription_context);

  static Status ProcessEvents(
      std::vector<Row>& emitted_row_list,
      AuditdFimProcessMap& process_map,
      const AuditdFimConfiguration& configuration,
      const std::vector<SyscallEvent>& syscall_event_list) noexcept;
};
}
