#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>
#include <chrono>
#include <glog/logging.h>
#include "openframe_token_extractor.h"
#include "openframe_authorization_manager.h"

namespace osquery {

class OpenframeTokenRefresher {
public:
    explicit OpenframeTokenRefresher(std::shared_ptr<OpenframeTokenExtractor> extractor);
    ~OpenframeTokenRefresher();

    // Start the token refresher with a fixed interval
    void start();
    void stop();

private:
    void process();

    std::atomic<bool> running_;
    std::mutex mutex_;
    std::thread refresh_thread_;
    std::shared_ptr<OpenframeTokenExtractor> extractor_;
};

} // namespace osquery 