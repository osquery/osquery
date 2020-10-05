/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <mutex>

#include <librdkafka/rdkafka.h>

#include <osquery/core/core.h>
#include <osquery/core/plugins/logger.h>
#include <osquery/dispatcher/dispatcher.h>

namespace osquery {

/// Name indicating default Kafka topic to publish to if payload name is not
/// found.
extern const std::string kKafkaBaseTopic;

/// Retrieves log payload field "name".
std::string getMsgName(const std::string& payload);

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

  KafkaProducerPlugin() : InternalRunnable("kafka_producer"), running_(false) {}
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
   * @brief Flushes all buffered messages to Kafka, waiting for a maximum of 3
   * seconds.  Wrapper with mutex locking around rd_kafka_flush.
   */
  virtual void flushMessages();

  /**
   * @brief polls to ensure onMsgDelivery callback is invoked message receipt.
   * Wrapper with mutex locking around rd_kafka_poll.
   */
  virtual void pollKafka();

  /// Boolean representing whether the logger is running.
  std::atomic<bool> running_;

  /// Map of query names to Kafka topic.
  std::map<std::string, rd_kafka_topic_t*> queryToTopics_;

 private:
  /// Configures Kafka topics accordingly.
  bool configureTopics();

  /// Initiates Kafka topic.  Caller needs to handle rd_kafka_topic_t* cleanup.
  rd_kafka_topic_t* initTopic(const std::string& topicName);

  /// Smart pointer to the Kafka producer.
  std::unique_ptr<rd_kafka_t, std::function<void(rd_kafka_t*)>> producer_;

  /// Vector of unique_ptr to the Kafka topic.
  std::vector<
      std::unique_ptr<rd_kafka_topic_t, std::function<void(rd_kafka_topic_t*)>>>
      topics_;

  /// OS hostname and binary name interpolated as the Kafka message key.
  std::string msgKey_;

  /// Mutex for managing access to the producer_ pointer.
  Mutex producerMutex_;

  /// Flag to ensure shutdown method is called only once
  static std::once_flag shutdownFlag_;
};
} // namespace osquery
