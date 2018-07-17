#include <sstream>
#include <string>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/tables.h>

#include "osquery/tables/events/windows/file_events.h"

namespace osquery {

  REGISTER(FileEventSubscriber, "event_subscriber", "windows_file_events");

  Status FileEventSubscriber::init() {
    LOG(WARNING) << "testing the warning system in FileEventSubscriber::init()";
    auto sc = createSubscriptionContext();
    sc->recursive = false;
    sc->opath = sc->path = std::string("C:\\Users\\Garret\\workspace\\test.txt");
    sc->mask = 0xFFFFFFFF;
    sc->category = "test";
    subscribe(&FileEventSubscriber::Callback, sc);
    return Status(0, "OK");
  }

  Status FileEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
    Row r;
    std::stringstream stm;
    stm << std::hex << ec->action;
    r["action"] = stm.str();
    r["target_path"] = ec->path;
    r["category"] = sc->category;

    add(r);
    return Status(0, "OK");
  }
}
