#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/events/freebsd/fsevents.h"

namespace osquery {
namespace tables {

class PasswdChangesEventSubscriber {
 public:
  QueryData genTable() {
    QueryData results;

    throw std::domain_error("Table not implemented for FreeBSD");

    return results;
  }
};
}
}
