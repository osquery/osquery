/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <osquery/dispatcher.h>
#include <osquery/ev2/manager.h>
#include <osquery/evgen/linux/udev.h>
#include <osquery/registry_factory.h>
#include <osquery/tables.h>

namespace osquery {

class UdevTable final
  : public TablePlugin
  , public InternalRunnable
  , public std::enable_shared_from_this<UdevTable> {
 public:
  UdevTable(std::shared_ptr<ev2::EventManager> em);
  ~UdevTable();

  void start() override;

 private:
  TableColumns columns() const override;
  TableAttributes attributes() const override;
  QueryData generate(QueryContext& context) override;

 private:
  std::shared_ptr<evgen::UdevSubscription> subscription_;
  std::shared_ptr<ev2::EventManager> em_;

  QueryData data_;
};

} // namespace osquery
