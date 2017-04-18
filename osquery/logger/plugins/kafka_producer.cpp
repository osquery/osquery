/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <unistd.h>

#include <future>
#include <memory>

#include <librdkafka/rdkafka.h>

#include <osquery/flags.h>
#include <osquery/logger.h>

namespace osquery {

FLAG(string,
     logger_kafka_brokers,
     "localhost",
     "Bootstrap broker(s) as a comma-separated list of host or host:port "
     "(default port 9092)");

FLAG(string,
     logger_kafka_topic,
     "osquery",
     "Kafka topic to publish logs under");

FLAG(string,
     logger_kafka_acks,
     "all",
     "The number of acknowledgments the Kafka producer requires the leader to "
     "have received before considering a request complete.  Valid values are "
     "'0', '1', and 'all'");

void delKafkaHandle(rd_kafka_t* k) {
  rd_kafka_destroy(k);
};

void delKafkaTopic(rd_kafka_topic_t* kt) {
  rd_kafka_topic_destroy(kt);
};

class KafkaProducerPlugin : public LoggerPlugin {
 public:
  /*
   * @brief Logs string s as payload to configured Kafka brokers.
   *
   * Calls rd_kafka_poll regardless of production success.  rd_kafka_poll
   * invokes callback that actually reports if message sends failed.
   */
  Status logString(const std::string& s) override;

  /**
   * @brief Initializes the Kafka producer.
   *
   * Setups producer with necessary configurations for interacting with Kafka
   * brokers.  Registers the os hostname as the Kafka client.id.
   */
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

  /**
   * @brief Flushes final messages.
   *
   * Checks if Kafka producer is running and if so, flushes remaining messages
   * to the brokers waiting a max of 3 seconds.
   */
  void stop();

  KafkaProducerPlugin() : running_(false) {}
  ~KafkaProducerPlugin();

  KafkaProducerPlugin(KafkaProducerPlugin const&) = delete;
  KafkaProducerPlugin& operator=(KafkaProducerPlugin const&) = delete;

 private:
  /// Smart pointer to the Kafka producer.
  std::unique_ptr<rd_kafka_t, std::function<void(rd_kafka_t*)>> producer_;

  /// Smart pointer to the Kafka topic.
  std::unique_ptr<rd_kafka_topic_t, std::function<void(rd_kafka_topic_t*)>>
      topic_;

  /// std::future object for background Kafka poll thread.
  std::future<void> futureTimer_;

  /// Boolean representing whether the logger is running.
  bool running_;

  /// OS hostname and binary name interpolated as the Kafka message key.
  std::string msgKey_;
};

REGISTER(KafkaProducerPlugin, "logger", "kafka_producer");

/**
 * @brief callback for status of message delivery
 *
 * Logs an error message for failed deliveries; does nothing if successful.
 * Callback is invoked by rd_kafka_poll.
 */
void onMsgDelivery(rd_kafka_t* rk,
                   const rd_kafka_message_t* rkmessage,
                   void* opaque) {
  if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR) {
    LOG(ERROR) << "Kafka message delivery failed: "
               << rd_kafka_err2str(rkmessage->err);
  }
}

KafkaProducerPlugin::~KafkaProducerPlugin() {
  stop();
}

void KafkaProducerPlugin::stop() {
  if (running_) {
    running_ = false;
    // wait for max 3 seconds
    rd_kafka_flush(producer_.get(), 3 * 1000);
  }
}

void KafkaProducerPlugin::init(const std::string& name,
                               const std::vector<StatusLogLine>& log) {
  // Get local hostname to use as client id and Kafka msg key.
  char hostname[sysconf(_SC_HOST_NAME_MAX)];
  if (gethostname(hostname, sizeof(hostname)) != 0) {
    LOG(ERROR) << "Could not get system local hostname.";
    return;
  }

  msgKey_ = std::string(hostname) + "_" + name;

  // Configure Kafka producer.
  char errstr[512];
  rd_kafka_conf_t* conf = rd_kafka_conf_new();

  if (rd_kafka_conf_set(conf, "client.id", hostname, errstr, sizeof(errstr)) !=
      RD_KAFKA_CONF_OK) {
    LOG(ERROR) << "Could not initiate Kafka client.id configuration:" << errstr;
    return;
  }

  if (rd_kafka_conf_set(conf,
                        "bootstrap.servers",
                        FLAGS_logger_kafka_brokers.c_str(),
                        errstr,
                        sizeof(errstr)) != RD_KAFKA_CONF_OK) {
    LOG(ERROR) << "Could not initiate Kafka brokers configuration: " << errstr;
    return;
  }

  // Register send callback.
  rd_kafka_conf_set_dr_msg_cb(conf, onMsgDelivery);

  // Create producer handle.
  std::unique_ptr<rd_kafka_t, std::function<void(rd_kafka_t*)>> rk(
      rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr)),
      delKafkaHandle);
  producer_.swap(rk);
  if (producer_.get() == nullptr) {
    LOG(ERROR) << "Could not initiate Kafka producer handle: " << errstr;
    return;
  }

  // Set topic configurations.
  rd_kafka_topic_conf_t* topicConf = rd_kafka_topic_conf_new();
  if (rd_kafka_topic_conf_set(topicConf,
                              "acks",
                              FLAGS_logger_kafka_acks.c_str(),
                              errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
    LOG(ERROR)
        << "Could not initiate Kafka request.required.acks configuration: "
        << errstr;
    return;
  }

  // Initiate Kafka topic.
  std::unique_ptr<rd_kafka_topic_t, std::function<void(rd_kafka_topic_t*)>> tk(
      rd_kafka_topic_new(
          producer_.get(), FLAGS_logger_kafka_topic.c_str(), topicConf),
      delKafkaTopic);
  topic_.swap(tk);
  if (topic_.get() == nullptr) {
    LOG(ERROR) << "Could not create Kafka topic " << FLAGS_logger_kafka_topic
               << ": " << rd_kafka_last_error();
    return;
  }

  // Start bg loop for polling to ensure onMsgDelivery callback is invoked even
  // at times were no messages are produced
  // (http://docs.confluent.io/2.0.0/clients/producer.html#asynchronous-writes)
  running_ = true;
  futureTimer_ = std::async(std::launch::async, [this]() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::seconds(5));
      rd_kafka_poll(producer_.get(), 0 /*non-blocking*/);
    }
  });
}

Status KafkaProducerPlugin::logString(const std::string& payload) {
  if (!running_) {
    return Status(
        1, "Cannot log because Kafka producer did not initiate properly.");
  }

  if (rd_kafka_produce(topic_.get(),
                       RD_KAFKA_PARTITION_UA,
                       RD_KAFKA_MSG_F_COPY,
                       (char*)payload.c_str(),
                       payload.length(),
                       msgKey_.c_str(), // Optional key
                       msgKey_.length(), // key length
                       NULL) == -1) {
    rd_kafka_poll(producer_.get(), 0 /*non-blocking*/);
    LOG(ERROR) << "Failed to produce on Kafka topic " +
                      std::string(rd_kafka_topic_name(topic_.get())) + " :" +
                      rd_kafka_err2str(rd_kafka_last_error());
    return Status(1,
                  "Failed to produce on Kafka topic " +
                      std::string(rd_kafka_topic_name(topic_.get())) + " :" +
                      rd_kafka_err2str(rd_kafka_last_error()));
  }
  // Poll after every produce attempt.
  rd_kafka_poll(producer_.get(), 0 /*non-blocking*/);
  return Status(0, "OK");
}
}
