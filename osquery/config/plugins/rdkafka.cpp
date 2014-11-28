#include <iostream>

#include "librdkafka/rdkafkacpp.h"

#include <glog/logging.h>
#include "osquery/logger/plugin.h"
#include "osquery/flags.h"

namespace osquery {

DEFINE_osquery_flag(string,
                    kafka_server,
                    "localhost",
                    "Hostname of Kafka server instance");

DEFINE_osquery_flag(int32, kafka_port, 9092, "Port of Kafka service");

DEFINE_osquery_flag(string, topic_key, "osquery", "Topic key");

DEFINE_osquery_flag(string, kafka_topic, "osquery", "Topic name");

class OsqueryKafkaDeliveryReportCb : public RdKafka::DeliveryReportCb {
public:
    void dr_cb(RdKafka::Message &message) {}
};

class RdkafkaPlugin : public LoggerPlugin {
    RdKafka::Producer *producer;
    RdKafka::Conf *conf;
    RdKafka::Conf *tconf;
    RdKafka::Topic *topic;

public:
RdkafkaPlugin() {
    std::string errstr;

    /*
    * Create configuration objects
    */
    conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
    tconf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);

    conf->set("metadata.broker.list", FLAGS_kafka_server, errstr);
    /* Set delivery report callback */
    // OsqueryKafkaDeliveryReportCb os_kafka_dr_cb;
    // conf->set("dr_cb", &os_kafka_dr_cb, errstr);

    /*
     * Create producer using accumulated global configuration.
     */
    producer = RdKafka::Producer::create(conf, errstr);
    if (!producer) {
        LOG(ERROR) << "Failed to create producer: " << errstr << std::endl;
        exit(1);
    }

    LOG(INFO) << "% Created producer " << producer->name() << std::endl;

    /*
     * Create topic handle.
     */
    topic = RdKafka::Topic::create(producer, FLAGS_kafka_topic, tconf, errstr);
    if (!topic) {
        LOG(ERROR) << "Failed to create topic: " << errstr << std::endl;
        exit(1);
    }
}

public:
Status logString(const std::string& message) {
    if (message.empty()) {
        producer->poll(0);
        return Status(0, "OK");
    }

    RdKafka::ErrorCode resp = producer->produce(topic, RdKafka::Topic::PARTITION_UA,
                                            RdKafka::Producer::MSG_COPY /* Copy payload */,
                                            const_cast<char *>(message.c_str()), message.size(),
                                            NULL, NULL
                                        );
    if (resp != RdKafka::ERR_NO_ERROR) {
        LOG(ERROR) << "Produce failed: " << RdKafka::err2str(resp) << std::endl;
    } else {
        LOG(INFO) << "Produced message (" << message.size() << " bytes)" << std::endl;
    }

    producer->poll(0);

    while (producer->outq_len() > 0) {
        producer->poll(500);
    }

    return Status(0, "OK");
}

virtual ~RdkafkaPlugin(){
    delete topic;
    delete producer;
    RdKafka::wait_destroyed(5000);
}
};

REGISTER_LOGGER_PLUGIN( "rdkafka", std::make_shared<osquery::RdkafkaPlugin>() );
}
