/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>
#include <type_traits>
#include <unordered_map>

#include "table_channel_base.h"

namespace osquery {
template <typename T>
struct GetChannelType;

template <typename TableChannelFactory>
class TableChannelFactoryBase {
 private:
  using TableChannel = typename GetChannelType<TableChannelFactory>::Channel;
  static_assert(
      std::is_base_of<TableChannelBase<TableChannel>, TableChannel>::value,
      "The TableChannel type do not implement the interface from "
      "TableChannelBase<TableChannel>");

 public:
  template <typename... ConstructorArgs>
  TableChannel& createChannel(const std::string table_name,
                              ConstructorArgs&&... args) {
    std::unique_ptr<TableChannel> channel =
        static_cast<TableChannelFactory&>(*this).createChannelImpl(
            table_name, std::forward<ConstructorArgs>(args)...);
    auto channel_ptr = channel.get();
    table_to_channel.emplace(table_name, std::move(channel));

    return *channel_ptr;
  }

  TableChannel* getTableChannel(const std::string& table_name) {
    auto it = table_to_channel.find(table_name);
    if (it != table_to_channel.end())
      return it->second.get();

    return nullptr;
  }

  void dropTableChannel(const std::string& table_name) {
    int erased = table_to_channel.erase(table_name);

    if (erased == 0) {
      throw std::logic_error("Trying to drop non existing channel to table " +
                             table_name);
    }
  }

  void clear() {
    table_to_channel.clear();
  }

 private:
  std::unordered_map<std::string, std::unique_ptr<TableChannel>>
      table_to_channel;
  TableChannelFactoryBase() {}
  friend TableChannelFactory;
};
} // namespace osquery
