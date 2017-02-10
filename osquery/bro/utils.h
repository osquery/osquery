#include <osquery/status.h>
#include <osquery/system.h>

#include "osquery/bro/BrokerManager.h"

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include <iostream>

namespace osquery {

    Status
    createSubscriptionRequest(const std::string &rType, const broker::message &msg, const std::string &incoming_topic,
                              SubscriptionRequest &sr);

    Status parseBrokerGroups(const std::string& json_groups, std::vector<std::string>& groups);


/////////////////////////////////////////////////////////
//////////////// Print Debug Methods/////////////////////
/////////////////////////////////////////////////////////

    void printColumnsInfo(const std::string &q);

    Status printQueryLogItemJSON(const std::string &json_string);

    Status printQueryLogItem(const QueryLogItem &item);

    void printDiffResults(const DiffResults &results);

    void printQueryData(const QueryData &data);

    void printDecorations(const std::map <std::string, std::string> &deco);


}
