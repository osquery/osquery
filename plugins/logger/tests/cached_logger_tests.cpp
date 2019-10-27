#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/dispatcher.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include <osquery/utils/json/json.h>
#include <plugins/logger/cached_logger.h>

using namespace testing;
namespace pt = boost::property_tree;

namespace osquery {

class CachedLoggerTests : public Test {
 public:

};

TEST_F(CachedLoggerTests, rotate_logic) {
  LoggerBounds bounds = {500 /* records */, 1024 /* record bytes */, 50000};
  LogChannel channel;
  time_t now = time(NULL);
  time_t minute_from_now = now + 60;
  time_t ten_seconds_ago = now - 10;
  channel.ts = ten_seconds_ago;
  channel.num_bytes = 4000;
  channel.num_lines = 0;
  size_t num_files_queued = 3;
  EXPECT_FALSE(CachedLoggerPlugin::_needsRotate(
      bounds, channel, now, 256, num_files_queued));

  // the following would be true, but file is empty. e.g. channel.num_lines==0
  EXPECT_FALSE(CachedLoggerPlugin::_needsRotate(
	  bounds, channel, minute_from_now, 256, num_files_queued));

  channel.num_lines = 1;
  EXPECT_TRUE(CachedLoggerPlugin::_needsRotate(
      bounds, channel, minute_from_now, 256, num_files_queued));

  channel.num_lines = 499;
  EXPECT_FALSE(CachedLoggerPlugin::_needsRotate(
      bounds, channel, now, 256, num_files_queued));
  channel.num_lines = 500;
  EXPECT_TRUE(CachedLoggerPlugin::_needsRotate(
      bounds, channel, now, 256, num_files_queued));
}

} // namespace osquery
