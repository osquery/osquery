/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <tob/linuxevents/ilinuxevents.h>

#include <osquery/core/tables.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/expected/expected.h>

#include <memory>

namespace osquery {

class BPFProcessEventsTable final : public TablePlugin {
 public:
  enum class ErrorCode {
    MemoryAllocationFailure,
  };

  using Ptr = std::shared_ptr<BPFProcessEventsTable>;
  static Expected<Ptr, ErrorCode> create();

  virtual ~BPFProcessEventsTable() override;

  const std::string& name() const;
  void addEvents(tob::linuxevents::ILinuxEvents::EventList event_list);

  BPFProcessEventsTable(const BPFProcessEventsTable&) = delete;
  BPFProcessEventsTable& operator=(const BPFProcessEventsTable&) = delete;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  BPFProcessEventsTable();

  virtual TableColumns columns() const override;
  virtual TableRows generate(QueryContext& context) override;
};

} // namespace osquery