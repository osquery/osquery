#include "osquery/events/windows/windows_file_events.h"

#include <osquery/tables.h>

namespace osquery {
class FileEventSubscriber : public EventSubscriber<FileEventPublisher> {
 public:
  Status init() override;
  Status Callback(const ECRef& ec, const SCRef& sc);
  void configure() override;
};
}
