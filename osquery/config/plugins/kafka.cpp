#include <iostream>

#include <libkafka/ApiConstants.h>
#include <libkafka/Client.h>
#include <libkafka/Packet.h>
#include <libkafka/Message.h>
#include <libkafka/MessageSet.h>
#include <libkafka/TopicNameBlock.h>
#include <libkafka/produce/ProduceMessageSet.h>
#include <libkafka/produce/ProduceRequest.h>
#include <libkafka/produce/ProduceResponsePartition.h>
#include <libkafka/produce/ProduceResponse.h>

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

LibKafka::Message* createMessage(const char *value, const char *key){
	// these will be updated as the message is prepared for production
	const static int crc = 1001;
	const static signed char magicByte = -1;
    // last three bits must be zero to disable gzip compression
	const static signed char attributes = 0;

    int value_len = strlen(value);
	unsigned char *v = new unsigned char[value_len];
    memcpy(v, value, value_len);

	unsigned char *k = new unsigned char[strlen(key)];
	memcpy( k, key, strlen(key) );

	return new LibKafka::Message(crc, magicByte, attributes, strlen(key),
	                   (unsigned char *) k, value_len, (unsigned char *) v, 0, true);
}

LibKafka::ProduceMessageSet* createProduceMessageSet(std::vector<LibKafka::Message*> message_vector, int message_set_size) {
    LibKafka::MessageSet* message_set = new LibKafka::MessageSet(message_set_size, message_vector, true);
    int wired_message_set_size = message_set->getWireFormatSize(false);
    // using partition = 0
    return new LibKafka::ProduceMessageSet(0, wired_message_set_size, message_set, true);
}

void sendProduceRequest(LibKafka::ProduceMessageSet** produceMessageSetArray) {
    LibKafka::Client *cli = new LibKafka::Client( FLAGS_kafka_server.c_str(), FLAGS_kafka_port );
    LibKafka::ProduceRequest* produce_request;
    const int REQUIRE_ACK = 1;
    const int TIMEOUT = 15;
    const static std::string client_id = "osquery-client";

    LibKafka::TopicNameBlock<LibKafka::ProduceMessageSet>* topic_name_block =
        new LibKafka::TopicNameBlock<LibKafka::ProduceMessageSet>(FLAGS_kafka_topic.c_str(), 1, produceMessageSetArray, true);

    LibKafka::TopicNameBlock<LibKafka::ProduceMessageSet>** produceTopicArray = new LibKafka::TopicNameBlock<LibKafka::ProduceMessageSet>*[1] {topic_name_block};

    produce_request = new LibKafka::ProduceRequest(0, client_id, REQUIRE_ACK, TIMEOUT, 1, produceTopicArray, true);

    LibKafka::ProduceResponse *response = cli->sendProduceRequest(produce_request);

    if (response == nullptr) {
        LOG(ERROR) << "an error ocurred while sending the produce request, errno = " << strerror(errno);
    } else {
        if ( response->hasErrorCode() ) {
            LOG(ERROR) << "publish error detected";
        } else {
            VLOG(1) << "message successfully published to kafka.";
        }
    }

    delete produce_request;
    if (response != nullptr) delete response;
}

class KafkaPlugin : public LoggerPlugin {

public:
KafkaPlugin() {
}

public:
Status logString(const std::string& message) {
	LibKafka::ProduceMessageSet** produceMessageSetArray = new LibKafka::ProduceMessageSet*[1];
    int message_set_array_index = 0;

    if (message.length() == 0) {
        return Status(0, "OK");
    }

    std::vector<LibKafka::Message*> message_vector;

    //TODO chop messages longer than 900 chars into small pieces
    // but sending multiple messages together result in segment fault
    int message_set_size = sizeof(long int) + sizeof(int);
    LibKafka::Message* _message = createMessage(message.c_str(), FLAGS_topic_key.c_str());
    int _message_size = _message->getWireFormatSize(false);
    message_vector.push_back(_message);
    message_set_size += _message_size;
    LibKafka::ProduceMessageSet* produce_message_set = createProduceMessageSet(message_vector, message_set_size);

    produceMessageSetArray[0] = produce_message_set;
    sendProduceRequest(produceMessageSetArray);

    delete[] produceMessageSetArray;
	return Status(0, "OK");
}

virtual ~KafkaPlugin(){
}
};

REGISTER_LOGGER_PLUGIN( "kafka", std::make_shared<osquery::KafkaPlugin>() );
}
