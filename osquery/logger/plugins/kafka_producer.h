/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <atomic>
#include <future>
#include <memory>
#include <mutex>

#include <librdkafka/rdkafka.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>

namespace osquery {

/// How often to poll Kafka broker for publish results.
const std::chrono::seconds kKafkaPollDuration = std::chrono::seconds(5);

class KafkaProducerPlugin : public LoggerPlugin, public InternalRunnable {
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

  KafkaProducerPlugin() : running_(false), topic_(nullptr) {}
  ~KafkaProducerPlugin() {}

  KafkaProducerPlugin(KafkaProducerPlugin const&) = delete;
  KafkaProducerPlugin& operator=(KafkaProducerPlugin const&) = delete;

 protected:
  /**
   * @brief Publishes message to Kafka topic.
   *
   * @param topic Kafka topic to publish to
   * @param msg message body
   *
   * @return Status of publish attempt
   */
  virtual Status publishMsg(rd_kafka_topic_t* topic,
                            const std::string& payload);

  /**
   * Flushes all buffered messages to Kafka, waiting for a maximum of 3
   * seconds.  Wrapper with mutex locking around rd_kafka_flush.
   */
  virtual void flushMessages();

  /**
   * polls to ensure onMsgDelivery callback is invoked message receipt.
   * Wrapper with mutex locking around rd_kafka_poll.
   */
  virtual void pollKafka();

  /// Boolean representing whether the logger is running.
  std::atomic<bool> running_;

 private:
  /// Smart pointer to the Kafka producer.
  std::unique_ptr<rd_kafka_t, std::function<void(rd_kafka_t*)>> producer_;

  /// Smart pointer to the Kafka topic.
  std::unique_ptr<rd_kafka_topic_t, std::function<void(rd_kafka_topic_t*)>>
      topic_;

  /// OS hostname and binary name interpolated as the Kafka message key.
  std::string msgKey_;

  /// Mutex for managing access to the producer_ pointer.
  Mutex producerMutex_;

  /// Flag to ensure shutdown method is called only once
  static std::once_flag shutdownFlag_;
};
} // namespace osquery
