/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <ctime>

#include <boost/optional.hpp>

#include <osquery/events/eventsubscriber.h>
#include <osquery/events/windows/windowseventlogpublisher.h>

namespace osquery {
class PowershellEventSubscriber
    : public EventSubscriber<WindowsEventLogPublisher> {
 public:
  PowershellEventSubscriber();
  virtual ~PowershellEventSubscriber() override;

  virtual Status init() override;
  Status Callback(const ECRef& event, const SCRef& subscription);

  struct Context final {
    using ScriptBlockID = std::string;

    struct ScriptMessage final {
      std::size_t expected_message_count{0U};
      std::size_t message_number{0U};

      ScriptBlockID script_block_id;
      std::string message;

      std::time_t osquery_time{0U};
      std::string event_time;

      std::string script_path;
      std::string script_name;
    };

    using ScriptMessageList = std::vector<ScriptMessage>;

    std::vector<double> character_frequency_map;
    std::unordered_map<ScriptBlockID, ScriptMessageList> script_state_map;

    std::vector<Row> row_list;

    std::time_t last_event_expiration_time{0U};
    std::size_t invalid_event_count{0U};
    std::size_t expired_event_count{0U};
  };

  static Status generateRow(
      Row& row,
      std::vector<Context::ScriptMessage> script_message_list,
      const std::vector<double>& character_frequency_map);

  static Status parseScriptMessageEvent(
      boost::optional<Context::ScriptMessage>& script_message_opt,
      const boost::property_tree::ptree& event);

  static Status processEventObject(Context& context,
                                   const boost::property_tree::ptree& event);

  static Status processEventExpiration(Context& context);

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d_;
};
} // namespace osquery
