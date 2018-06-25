For details on how **osqueryd** schedules queries and loads information from a config, see the [configuration](../deployment/configuration.md) deployment guide.

You may distribute configurations in your environment differently than Facebook. To support all environments, the way that **osqueryd** goes about retrieving configurations is completely pluggable and configurable. By default, **osqueryd** will look for a JSON file on disk using the default config plugin: **filesystem**. If you distribute configurations via something like [Zookeeper](http://zookeeper.apache.org/) or [etcd](https://github.com/coreos/etcd), you need to write a C++ function that can acquire a string of JSON. This developer tutorial will walk through the default filesystem config plugin as a demonstration for creating new config inputs.

## Example: Filesystem config

The following code is more-or-less the **filesystem** config plugin. This is the default config plugin, it simply reads JSON data from a flat file. Let's walk through the implementation:

```cpp
// Note 1: REQUIRED includes
#include <osquery/config.h>
#include <osquery/flags.h>

namespace osquery {

// Note 2: Setup any invocation arguments
FLAG(string, config_path, "osquery.conf", "Path to config");

// Note 3: Inherit from ConfigPlugin
class FilesystemConfigPlugin : public ConfigPlugin {
 public:
  osquery::Status genConfig(std::map<std::string, std::string>& config) {
    std::string content;
    std::ifstream content_stream(FLAGS_config_path);

    content_stream.seekg(0, std::ios::end);
    content.reserve(config_stream.tellg());
    content_stream.seekg(0, std::ios::beg);

    content.assign((std::istreambuf_iterator<char>(content_stream)),
                    std::istreambuf_iterator<char>());

    // Note 4: Return an osquery Status and JSON encoded config.
    config["default_source"] = std::move(content);
    return Status(0, "OK");
  }
};

// Note 5: Register the plugin
REGISTER(FilesystemConfigPlugin, "config", "filesystem");
}
```

There are 5 parts of a config plugin:

- Include the plugin macros as well as command line argument macros.
- If your config requires customization expose it as arguments.
- Inherit from `ConfigPlugin` and implement: `osquery::Status genConfig(std::map<std::string, std::string>&)**`.
- Return an osquery Status and map of config sources to JSON-encoded strings.
- Register the plugin using a string-identifier.

The filesystem plugin is very very simple the config plugin architecture expects config plugins to yield valid JSON.

**Additional overloads**

Packs may be retrieved subsequently after a configuration is read. If pack content is not provided inline with the configuration the string value is passed to the plugin. The config plugin in question must implement the virtual
method:

```cpp
Status genPack(const std::string& name, const std::string& value, std::string& pack);
```

## Using the plugin

Now when starting **osqueryd** you may use `--config_plugin=yourconfigpluginname` where the name is the string identifier used in **REGISTER**.
