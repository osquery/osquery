#include <sstream>
#include <string>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/tables.h>

#include "osquery/tables/events/event_utils.h"
#include "osquery/tables/events/windows/file_events.h"

namespace osquery {

REGISTER(FileEventSubscriber, "event_subscriber", "windows_file_events");

Status FileEventSubscriber::init() {
  return Status(0, "OK");
}

void FileEventSubscriber::configure() {
  // Clear all monitors from INotify.
  // There may be a better way to find the set intersection/difference.
  removeSubscriptions();

  auto parser = Config::getParser("file_paths");
  auto& accesses = parser->getData().doc()["file_accesses"];
  Config::get().files([this, &accesses](const std::string& category,
                                        const std::vector<std::string>& files) {
    for (const auto& file : files) {
      VLOG(1) << "Added file event listener to: " << file;
      auto sc = createSubscriptionContext();
      // Use the filesystem globbing pattern to determine recursiveness.
      sc->recursive = 0;
      sc->opath = sc->path = file;
      sc->mask = kFileDefaultMask;

      // don't support access tracking at the moment

      sc->category = category;
      subscribe(&FileEventSubscriber::Callback, sc);
    }
  });
}

Status FileEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  std::stringstream stm;
  stm << std::hex << ec->action;
  r["action"] = stm.str(); //TODO: translate bitfield into strings
  r["target_path"] = ec->path;
  r["category"] = sc->category;
  r["transaction_id"] = std::to_string(ec->record.Usn);

  //TODO: only decorate on create/update/rename_new, because after a delete/rename_old it's too late
  decorateFileEvent(ec->path, false, r);

  add(r);
  return Status(0, "OK");
}
}
