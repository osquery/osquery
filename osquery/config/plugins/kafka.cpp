#include "osquery/logger/plugin.h"
#include "osquery/flags.h"

#include "stdio.h"
#include <iostream>
#include <libkafka/ApiConstants.h>
#include <libkafka/Client.h>
#include <libkafka/Message.h>
#include <libkafka/MessageSet.h>
#include <libkafka/TopicNameBlock.h>
#include <libkafka/produce/ProduceMessageSet.h>
#include <libkafka/produce/ProduceRequest.h>
#include <libkafka/produce/ProduceResponsePartition.h>
#include <libkafka/produce/ProduceResponse.h>

using namespace std;
using namespace LibKafka;

namespace osquery {

DEFINE_osquery_flag(string,
                    kafka_server,
                    "localhost",
                    "Hostname of Kafka server instance");

DEFINE_osquery_flag(string, kafka_port, "9092", "Port of Kafka service");

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
	                   (unsigned char *) k, strlen(value), (unsigned char *) v, 0, true);
}

class KafkaPlugin : public LoggerPlugin {

public:
KafkaPlugin(){
}

public:
Status logString(const string& message){
	istringstream stream_message(message);

	vector<Message*> message_vector;
	int message_set_size;
	MessageSet* message_set;
	ProduceMessageSet* produce_message_set;
	TopicNameBlock<ProduceMessageSet>* topic_name_block;
	TopicNameBlock<ProduceMessageSet>** produceTopicArray;
	ProduceMessageSet** produceMessageSetArray;
	ProduceRequest* produce_request;

	while ( !stream_message.eof() ) {
		string message_line;
		Message* message_;
		getline(stream_message, message_line);
        if (message_line.length() == 0) continue;
        if (message_line.length() > 200) {
            cout << message_line << endl;
            cout << "message length: " << message_line.length() << endl;
            string tuncated_message = message_line.substr(0, 50);
            message_ = createMessage(tuncated_message.c_str(), "osquery");
        } else {
            message_ = createMessage(message_line.c_str(), "osquery");
        }
		message_set_size += sizeof(long int) + sizeof(int) + message_->getWireFormatSize(false);
		message_vector.push_back(message_);
	}
	message_set = new MessageSet(message_set_size, message_vector, true);

	int messageSetSize = message_set->getWireFormatSize(false);
	// using partition = 0
	produce_message_set = new ProduceMessageSet(0, messageSetSize, message_set, true);
	produceMessageSetArray = new ProduceMessageSet*[1] {produce_message_set};
	topic_name_block = new TopicNameBlock<ProduceMessageSet>("osquery", 1, produceMessageSetArray, true);
	produceTopicArray = new TopicNameBlock<ProduceMessageSet>*[1] {topic_name_block};

	produce_request = new ProduceRequest(2202, "osquery-client", 1, 15, 1, produceTopicArray, true);
	// cout << *produce_request << endl;
	Client *cli = new Client( FLAGS_kafka_server.c_str(), stoi(FLAGS_kafka_port) );

	ProduceResponse *response = cli->sendProduceRequest(produce_request);

	if (response == NULL)
		cerr << "an error ocurred while sending the produce request, errno = " << strerror(errno) << "\n";
	else {
		if ( response->hasErrorCode() )
			cerr << "publish error detected\n";
		else
			cout << "message successfully published to kafka\n";
	}

	// cout << *produce_request << endl;
	// cout << *response << endl;
	delete produce_request;
	if (response != NULL)
		delete response;

	return Status(0, "OK");
}

virtual ~KafkaPlugin(){
}
};

REGISTER_LOGGER_PLUGIN( "kafka", std::make_shared<osquery::KafkaPlugin>() );
}
