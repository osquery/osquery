#include "osquery/logger/plugin.h"
#include "osquery/flags.h"

#include "stdio.h"
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

using namespace std;
using namespace LibKafka;

namespace osquery {

DEFINE_osquery_flag(string,
                    kafka_server,
                    "localhost",
                    "Hostname of Kafka server instance");

DEFINE_osquery_flag(string, kafka_port, "9092", "Port of Kafka service");

DEFINE_osquery_flag(string, topic_key, "osquery", "Topic key");

DEFINE_osquery_flag(string, kafka_topic, "osquery", "Topic name");

Message* createMessage(const char *value, const char *key){
	// these will be updated as the message is prepared for production
	const static int crc = 1001;
	const static signed char magicByte = -1;
	const static signed char attributes = 0;     // last three bits must be zero to disable gzip compression

	unsigned char *v = new unsigned char[strlen(value)];

	memcpy( v, value, strlen(value) );

	unsigned char *k = new unsigned char[strlen(key)];
	memcpy( k, key, strlen(key) );

	return new Message(crc, magicByte, attributes, strlen(key),
	                   (unsigned char *) k, strlen(value), (unsigned char *) v, 0, false);
}

ProduceMessageSet* createProduceMessageSet(vector<Message*> message_vector, int message_set_size) {
    MessageSet* message_set = new MessageSet(message_set_size, message_vector, false);
    int wired_message_set_size = message_set->getWireFormatSize(false);
    // using partition = 0
    return new ProduceMessageSet(0, wired_message_set_size, message_set, false);
}

void sendProduceRequest(ProduceMessageSet** produceMessageSetArray) {
    Client *cli = new Client( FLAGS_kafka_server.c_str(), stoi(FLAGS_kafka_port) );
    ProduceRequest* produce_request;
    const int REQUIRE_ACK = 1;
    const int TIMEOUT = 15;

    TopicNameBlock<ProduceMessageSet>* topic_name_block =
        new TopicNameBlock<ProduceMessageSet>(FLAGS_kafka_topic.c_str(), 1, produceMessageSetArray, false);

    TopicNameBlock<ProduceMessageSet>** produceTopicArray = new TopicNameBlock<ProduceMessageSet>*[1] {topic_name_block};

    produce_request = new ProduceRequest(0, "osquery-client", REQUIRE_ACK, TIMEOUT, 1, produceTopicArray, false);

    ProduceResponse *response = cli->sendProduceRequest(produce_request);

    if (response == NULL)
        LOG(ERROR) << "an error ocurred while sending the produce request, errno = " << strerror(errno);
    else {
        if ( response->hasErrorCode() )
            LOG(ERROR) << "publish error detected";
        else
            LOG(INFO) << "message successfully published to kafka.";
    }

    delete produce_request;
    if (response != NULL)
        delete response;
}

class KafkaPlugin : public LoggerPlugin {

public:
KafkaPlugin() {
}

public:
Status logString(const string& message) {
    cout << message << endl;
	ProduceMessageSet** produceMessageSetArray = new ProduceMessageSet*[1];
    int message_set_array_index = 0;

    if (message.length() == 0) {
        return Status(0, "OK");
    }

    vector<Message*> message_vector;

    message_vector.clear();

    int message_set_size = sizeof(long int) + sizeof(int);
    Message* _message = createMessage(message.c_str(), FLAGS_topic_key.c_str());
    int _message_size = _message->getWireFormatSize(false);
    message_vector.push_back(_message);
    message_set_size += _message_size;
    ProduceMessageSet* produce_message_set = createProduceMessageSet(message_vector, message_set_size);

    produceMessageSetArray[0] = produce_message_set;
    sendProduceRequest(produceMessageSetArray);

	return Status(0, "OK");
}

virtual ~KafkaPlugin(){
}
};

REGISTER_LOGGER_PLUGIN( "kafka", std::make_shared<osquery::KafkaPlugin>() );
}
