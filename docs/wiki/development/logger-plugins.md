For details on how osqueryd schedules queries and loads information from a config, see [using-osqueryd](../introduction/using-osqueryd).

If you'd like to use services like [scribe](https://github.com/facebookarchive/scribe) or [flume](http://flume.apache.org/), you need to write a C++ function that consumes/handles a string argument.

Consider the following example for logging results to the application's info log:

```cpp
#include <osquery/logger.h>
#include <glog/logging.h>

namespace osquery {

class GlogPlugin : public LoggerPlugin {
 public:
  Status logString(const std::string& message) {
    LOG(INFO) << message;
    return Status(0, "OK");
  }

  virtual ~GlogPlugin() {}
};

REGISTER(GlogPlugin, "logger", "glog");
}
```

Essentially, you're just implementing `logString`.

Once you you have built a logger plugin, it's automatically built into the available options for `--logger_plugin` as a result of your `REGISTER` call. That's it.