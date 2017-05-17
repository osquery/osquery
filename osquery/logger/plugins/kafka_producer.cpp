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

#include <atomic>
#include <future>
#include <memory>
#include <mutex>

#include <librdkafka/rdkafka.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/system.h>

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

const std::chrono::seconds kKafkaPollDuration = std::chrono::seconds(5);

void delKafkaHandle(rd_kafka_t* k) {
  rd_kafka_destroy(k);
};

void delKafkaTopic(rd_kafka_topic_t* kt) {
  rd_kafka_topic_destroy(kt);
};

class KafkaBgPoller;

class KafkaProducerPlugin final : public LoggerPlugin, public InternalRunnable {
  friend class KafkaBgPoller;

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
   * @brief InternalRunnable entry point that waits and polls Kafka
   *
   * If interrupted, invokes shutdown method
   */
  void start() override;

  /**
   * @brief Flushes final messages.
   *
   * Checks if Kafka producer is running and if so, flushes remaining messages
   * to the brokers waiting a max of 3 seconds.
   */
  void stop() override;

  KafkaProducerPlugin() : running_(false) {}
  ~KafkaProducerPlugin() {}

  KafkaProducerPlugin(KafkaProducerPlugin const&) = delete;
  KafkaProducerPlugin& operator=(KafkaProducerPlugin const&) = delete;

 private:
  /**
   * Flushes all buffered messages to Kafka, waiting for a maximum of 3
   * seconds.  Wrapper with mutex locking around rd_kafka_flush.
   */
  void flushMessages();

  /**
   * polls to ensure onMsgDelivery callback is invoked message receipt.
   * Wrapper with mutex locking around rd_kafka_poll.
   */
  void pollKafka();

  /// Smart pointer to the Kafka producer.
  std::unique_ptr<rd_kafka_t, std::function<void(rd_kafka_t*)>> producer_;

  /// Smart pointer to the Kafka topic.
  std::unique_ptr<rd_kafka_topic_t, std::function<void(rd_kafka_topic_t*)>>
      topic_;

  /// std::future object for background Kafka poll thread.
  std::future<void> futureTimer_;

  /// Boolean representing whether the logger is running.
  std::atomic<bool> running_;

  /// OS hostname and binary name interpolated as the Kafka message key.
  std::string msgKey_;

  /// Mutex for managing access to the producer_ pointer.
  Mutex producerMutex_;

  /// Flag to ensure shutdown method is called only once
  static std::once_flag shutdownFlag_;
};

REGISTER(KafkaProducerPlugin, "logger", "kafka_producer");

std::once_flag KafkaProducerPlugin::shutdownFlag_;

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

void KafkaProducerPlugin::flushMessages() {
  WriteLock lock(producerMutex_);
  rd_kafka_flush(producer_.get(), 3 * 1000);
}

void KafkaProducerPlugin::pollKafka() {
  WriteLock lock(producerMutex_);
  rd_kafka_poll(producer_.get(), 0 /*non-blocking*/);
}

void KafkaProducerPlugin::start() {
  while (!interrupted()) {
    pauseMilli(kKafkaPollDuration);
    if (interrupted()) {
      return;
    }

    pollKafka();
  }
}

void KafkaProducerPlugin::stop() {
  std::call_once(shutdownFlag_, [this]() {
    if (running_.load()) {
      running_.store(false);
      flushMessages();
    }
  });
}

void KafkaProducerPlugin::init(const std::string& name,
                               const std::vector<StatusLogLine>& log) {
  // Get local hostname to use as client id and Kafka msg key.
  std::string hostname(getHostname());

  msgKey_ = hostname + "_" + name;

  // Configure Kafka producer.
  char errstr[512];
  rd_kafka_conf_t* conf = rd_kafka_conf_new();

  if (rd_kafka_conf_set(
          conf, "client.id", hostname.c_str(), errstr, sizeof(errstr)) !=
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
  running_.store(true);
  futureTimer_ = std::async(std::launch::async, [this]() { start(); });
}

Status KafkaProducerPlugin::logString(const std::string& payload) {
  if (!running_.load()) {
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
    pollKafka();
    LOG(ERROR) << "Failed to produce on Kafka topic " +
                      std::string(rd_kafka_topic_name(topic_.get())) + " :" +
                      rd_kafka_err2str(rd_kafka_last_error());
    return Status(1,
                  "Failed to produce on Kafka topic " +
                      std::string(rd_kafka_topic_name(topic_.get())) + " :" +
                      rd_kafka_err2str(rd_kafka_last_error()));
  }
  // Poll after every produce attempt.
  pollKafka();
  return Status(0, "OK");
}
} // namespace osquery
