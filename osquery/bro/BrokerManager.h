#pragma once

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include "osquery/bro/QueryManager.h"

#include <osquery/database.h>
#include <osquery/status.h>
#include <osquery/system.h>

#include <iostream>
#include <list>
#include <algorithm>

namespace osquery {

    class BrokerManager {

    private:
        BrokerManager();

    public:

        // Get a singleton instance
        static BrokerManager* getInstance() {
            if (!_instance)
                _instance = new BrokerManager ();
            return _instance;
        }

        // Topic Prefix
        const std::string TOPIC_PREFIX = "/bro/osquery/";
        const std::string TOPIC_ALL = this->TOPIC_PREFIX + "all";
        const std::string TOPIC_ANNOUNCE = this->TOPIC_PREFIX + "announce";
        const std::string TOPIC_PRE_INDIVIDUALS = this->TOPIC_PREFIX + "uid/";
        const std::string TOPIC_PRE_GROUPS = this->TOPIC_PREFIX + "group/";
        const std::string TOPIC_PRE_CUSTOMS = this->TOPIC_PREFIX + "custom/";

        // Event messages
        const std::string EVENT_HOST_NEW = "osquery::host_new";
        const std::string EVENT_HOST_JOIN = "osquery::host_join";
        const std::string EVENT_HOST_LEAVE = "osquery::host_leave";
        const std::string EVENT_HOST_EXECUTE =  "osquery::host_execute";
        const std::string EVENT_HOST_SUBSCRIBE =  "osquery::host_subscribe";
        const std::string EVENT_HOST_UNSUBSCRIBE =  "osquery::host_unsubscribe";

        osquery::Status setNodeID(const std::string& uid);

        std::string getNodeID();

        osquery::Status addGroup(const std::string& group);

        osquery::Status removeGroup(const std::string& group);

        std::vector<std::string> getGroups();

        osquery::Status createEndpoint(std::string ep_name);

        broker::endpoint* getEndpoint();

        osquery::Status createMessageQueue(const std::string& topic);

        osquery::Status deleteMessageQueue(const std::string& topic);

        broker::message_queue* getMessageQueue(const std::string& topic);

        osquery::Status getTopics(std::vector<std::string>& topics);

        osquery::Status peerEndpoint(std::string ip, int port);

        osquery::Status logQueryLogItemToBro(const osquery::QueryLogItem& qli);

        osquery::Status sendEvent(const std::string& topic, const broker::message& msg);

    private:
        // The singleton object
        static BrokerManager* _instance;

        QueryManager* qm = nullptr;

        // The ID identifying the node (private channel)
        std::string nodeID = "";
        // The groups of the node
        std::vector<std::string> groups;
        // The Broker Endpoint
        broker::endpoint* ep = nullptr; // delete afterwards

        //  Key: topic_Name, Value: message_queue
        std::map<std::string, broker::message_queue*> messageQueues;

    };

}
