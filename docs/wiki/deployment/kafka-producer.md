Logging support utilizing a Kafka producer.

## Kafka Producer

Users can configure logs to be directly published to a Kafka topic.


### Configuration

Currently only 3 Kafka configurations are exposed: a comma delimited list of brokers with or without the port (by default `9092`) [default value: `localhost`], topic name [default value: `osquery`], and acks (the number acknowledgments the logger requires from the Kafka leader before the considering the request complete) [default: `all`; valid values: `0`, `1`, `all`]. [See official documentation for more details.](https://kafka.apache.org/documentation/#producerconfigs)

The configuration parameters are exposed via command line options and can be set in a JSON configuration file as exampled here:
```json
{
  "options": {
    "logger_kafka_brokers": "some.example1.com:9092,some.example2.com:9092",
    "logger_kafka_topic": "osquery_logs",
    "logger_kafka_acks": "1"
  }
}
```

Client ID and msg key used are a concatenation of the OS hostname and binary name (argv[0]).  Currently there can only be one topic passed into the configuration, so all logs will be published to the same topic.
