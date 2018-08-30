/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include "osquery/tables/system/linux/udev.h"

#include <tuple>

namespace osquery {

UdevTable::UdevTable(std::shared_ptr<ev2::EventManager> em)
  : InternalRunnable("table:udev")
  , subscription_(std::make_shared<evgen::UdevSubscription>("table:udev"))
  , em_(std::move(em))
{
  em_->bind(subscription_);

  auto wptr = std::shared_ptr<UdevTable>( this, [](UdevTable*){} );
  auto registry = RegistryFactory::get().registry("table");
  registry->add("udev", shared_from_this(), false);
}

UdevTable::~UdevTable()
{
}

void UdevTable::start()
{
  while (true) {
    int n = subscription_->wait();
    for (int i = 0; i < n; i++) {
      auto event = subscription_->get();

      Row r;
      r["id"] = std::to_string(event.id);
      r["action"] = evgen::UdevEvent::actionToString(event.action);
      r["subsystem"] = event.subsystem;
      r["devnode"] = event.devnode;
      r["devtype"] = event.devtype;
      r["driver"] = event.driver;
      data_.push_back(std::move(r));
    }
  }
}

TableColumns UdevTable::columns() const
{
  return {
    std::make_tuple("id", INTEGER_TYPE, ColumnOptions::INDEX),
    std::make_tuple("action", TEXT_TYPE, ColumnOptions::DEFAULT),
    std::make_tuple("subsystem", TEXT_TYPE, ColumnOptions::DEFAULT),
    std::make_tuple("devnode", TEXT_TYPE, ColumnOptions::DEFAULT),
    std::make_tuple("devtype", TEXT_TYPE, ColumnOptions::DEFAULT),
    std::make_tuple("driver", TEXT_TYPE, ColumnOptions::DEFAULT),
  };
}

TableAttributes UdevTable::attributes() const
{
  return TableAttributes::NONE;
}

QueryData UdevTable::generate(QueryContext& context)
{
  return data_;
}

} // namespace osquery
