# The osquery SDK

The osquery "public API" or SDK is the set of osquery headers and a subset of the source "cpp" files implementing what we call osquery **core**. The core code can be thought of as the framework or platform, it is everything except for the SQLite code and most table implementations. The public headers can be found in [/osquery/osquery/sdk/](https://github.com/osquery/osquery/tree/master/osquery/sdk).

osquery is organized into a **core**, **additional**, and **testing** during a default build from source. We call the set of public headers implementing **core** the 'osquery SDK'. This SDK can be used to build osquery outside of our CMake build system with a minimum set of dependencies. This organization better isolates OS API dependencies from development tools and libraries and provides a logical separation between code needed for extensions and module compiling.

The public API and SDK headers are documented via **doxygen**. To generate web-based documentation, you will need to install doxygen, run `make docs` from the repository root, then open `./build/docs/html/index.html`.

## Extensions

Extensions are separate processes that communicate over a [Thrift](https://thrift.apache.org/) IPC channel to osquery **core** in order to register one or more plugins or virtual tables. An extension allows you to develop independently: it may be compiled and linked using an external build system, against proprietary code. Your extension will be version-compatible with our publicly-built binary packages on [https://osquery.io/downloads](https://osquery.io/downloads).

Extensions use osquery's [Thrift API](https://github.com/osquery/osquery/blob/master/osquery/extensions/thrift/osquery.thrift) to communicate between `osqueryi` or `osqueryd` and the extension process. Extensions are commonly written in C++, but can also be developed [in Python](https://github.com/osquery/osquery-python), [in Go](https://github.com/kolide/osquery-go), or in really any language that supports [Thrift](https://thrift.apache.org/).

Only the osquery SDK provides the simple `startExtension` symbol that manages the life of your process, including the Thrift service threads and a watchdog.

osquery extensions should statically link the **core** code and use the `<osquery/sdk.h>` helper include file. C++ extensions should link: boost, thrift, glog, gflags, and optionally rocksdb for eventing. Let's walk through a basic example extension in C++ (source for [read_only_table/main.cpp](https://github.com/osquery/osquery/tree/master/external/examples)):

```cpp
// Note 1: Include the SDK and helpers
#include <osquery/core/system.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

using namespace osquery;

// Note 2: Define at least one plugin or table.
class ExampleTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
      std::make_tuple("example_text", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("example_integer", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

  TableRows generate(QueryContext& request) {
    TableRows results;

    auto r = make_table_row();
    r["example_text"] = "example";
    r["example_integer"] = INTEGER(1);

    results.push_back(std::move(r));
    return results;
  }
};

// Note 3: Use REGISTER_EXTERNAL to define your plugin or table.
REGISTER_EXTERNAL(ExampleTablePlugin, "table", "example");

int main(int argc, char* argv[]) {
  // Note 4: Start logging, threads, etc.
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  // Note 5: Connect to osqueryi or osqueryd.
  auto status = startExtension("example", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return runner.shutdown(0);
}
```

The `osqueryi` or `osqueryd` processes start an "extension manager" Thrift service thread that listens for extension register calls on a UNIX domain socket. Extensions may only communicate if the processes can read/write to this socket. An extension process running as a non-privileged user cannot register plugins to an `osqueryd` process running as root. Both the osquery core and C++ extensions using `startExtension` will deregister plugins if the communication becomes latent. Both of these settings are configurable using gflags or the osquery config options.

### Using the example extension

Please see the deployment [guide on extensions](../deployment/extensions.md) for a more-complete overview of how and why extensions are used.

If you [build from source](../development/building.md), you will build an example extension. The code can be found in the [`osquery/external/examples`](https://github.com/osquery/osquery/tree/master/external/examples) folder; it adds a config plugin called "example" and additional table called "example". There are two ways to run an extension: load the extension at an arbitrary time after shell or daemon execution, or request an "autoload" of extensions. The auto-loading method has several advantages, such as allowing dependencies on external config plugins and inheriting the same process monitoring as is applied to the osquery core worker processes.

The `osqueryi` shell also allows a quick and easy command-line autoload using `--extension`. Let's review both options.

First, to load the example extension in the osquery interactive shell, we start osqueryi:

```sh
$ ./build/darwin/osquery/osqueryi
osquery> SELECT path FROM osquery_extensions;
+-------------------------------------+
| path                                |
+-------------------------------------+
| /Users/USERNAME/.osquery/shell.em   |
+-------------------------------------+
osquery> ^Z
[1]  + 98777 suspended  ./build/darwin/osquery/osqueryi
```

Here we have started the osquery shell process, inspected the UNIX domain socket path it uses to communicate with extension processes, and then suspended the process temporarily.

```sh
$ ./build/darwin/osquery/example_extension.ext --help
osquery 1.7.0, your OS as a high-performance relational database
Usage: example_extension.ext [OPTION]...

osquery extension command line flags:

    --interval VALUE  Seconds delay between connectivity checks
    --socket VALUE    Path to the extensions UNIX domain socket
    --timeout VALUE   Seconds to wait for autoloaded extensions

osquery project page <https://osquery.io>.
$ ./build/darwin/osquery/example_extension.ext --socket /Users/USERNAME/.osquery/shell.em &
```

Before executing the extension we've inspected the potential CLI flags, which are a subset of the shell or daemon's [CLI flags](../installation/cli-flags.md). We executed the example extension in the background, so now we can resume the osquery shell and use the 'example' table provided by the extension.

```sh
[2] 98795
$ fg
[1]  - 98777 continued  ./build/darwin/osquery/osqueryi
osquery> SELECT * FROM example;
+--------------+-----------------+
| example_text | example_integer |
+--------------+-----------------+
| example      | 1               |
+--------------+-----------------+
osquery>
```

If the responsible osquery shell or daemon process ends, the extension will detect the loss of communication and also shutdown soon after. Read more about the lifecycle of extensions in the deployment guide.

The second, and simpler, way to manually load an extension is at the osqueryi command line with `--extension`:

```sh
./build/darwin/osquery/osqueryi --extension ./build/darwin/osquery/example_extension.ext
```

### Building external extensions

Your "external" extension, in the sense that the code is developed and contained somewhere external from the osquery repository, can be built semi-automatically.

1. Symlink your external extension source code directory into `./external`. (`ln -s [extension_source_dir] [osquery_external_subdir]` on Linux or macOS, `mklink /D [osquery_external_subdir] [extension_source_dir]` on Windows)
2. Make sure the symlink contains `extension_` as a prefix.
3. Run `make externals`.

This will find and compile all `.*\.{cpp,c,mm}` files within your external directory. If you need something more complicated, add a `CMakeLists.txt` to your directory and add your targets to the `externals` target.

See [`/osquery/external/cmake/cmakelibs.cmake`](https://github.com/osquery/osquery/blob/master/external/cmake/cmakelibs.cmake) for more information about the `addOsqueryExtension` and `addOsqueryExtensionEx` CMake macros.

Example:

```sh
(osquery) $ ln -s ~/git/fun-osquery-extension ./external/extension_fun
(osquery) $ ls ./external/extension_fun/
fun.cpp
(osquery) $ make externals
[...]
[100%] Built target libosquery
Scanning dependencies of target external_extension_awesome
[100%] Building CXX object external/CMakeFiles/external_extension_fun.dir/extension_fun/fun.cpp.o
[100%] Linking CXX executable external_extension_fun.ext
[100%] Built target external_extension_fun
[100%] Built target externals
```

## Bundling multiple extensions into a single-executable extension

All of the extensions declared with the **add_osquery_extension_ex()** CMake function will be automatically bundled into a single executable.

The executable name and version can be changed using the following two environment variables:

1. `OSQUERY_EXTENSION_GROUP_NAME` (default: `osquery_extension_group`)
2. `OSQUERY_EXTENSION_GROUP_VERSION` (default: `1.0`)

It is important to provide a header file that can be included by the generated main.cpp file; its purpose is to define the types used by the **REGISTER_EXTERNAL** directive.

An example is included in the `osquery/examples/extension_group_example`.

Please note that when using bundling, the source directory of each extension is added to the `include` list; developers should always use uniquely named include files. Additionally, if you are using RapidJSON documents in your extension, then you should instead leverage the osquery `json.h` header to avoid linking issues due to how we have configured RapidJSON `#define`s.

## Thrift API

[Thrift](https://thrift.apache.org/) is a code-generation/cross-language service development framework. osquery uses Thrift to allow extensions to implement plugins for config retrieval, log export, table implementations, event subscribers, and event publishers. We also use Thrift to wrap our SQL implementation using SQLite.

### Extension API

An extension process should implement the following API. During an extension's set up it will "broadcast" all of its registered plugins to the osquery shell or daemon process. Then the extension will be asked to start a UNIX domain socket and Thrift service thread implementing the `ping` and `call` methods.

```thrift
service Extension {
  /// Ping to/from an extension and extension manager for metadata.
  ExtensionStatus ping(),
  /// Call an extension (or core) registry plugin.
  ExtensionResponse call(
    /// The registry name (e.g., config, logger, table, etc.).
    1:string registry,
    /// The registry item name (plugin name).
    2:string item,
    /// The Thrift-equivalent of an osquery::PluginRequest.
    3:ExtensionPluginRequest request),
}
```

When an extension becomes unavailable, the shell or daemon process will automatically deregister those plugins.

### Extension Manager API (osqueryi/osqueryd)

```thrift
service ExtensionManager extends Extension {
  /// Return the list of active registered extensions.
  InternalExtensionList extensions(),
  /// Return the list of bootstrap or configuration options.
  InternalOptionList options(),
  /// The API endpoint used by an extension to register its plugins.
  ExtensionStatus registerExtension(
    1:InternalExtensionInfo info,
    2:ExtensionRegistry registry),
  ExtensionStatus deregisterExtension(
    1:ExtensionRouteUUID uuid,
  ),
  /// Allow an extension to query using an SQL string.
  ExtensionResponse query(
    1:string sql,
  ),
  /// Allow an extension to introspect into SQL used in a parsed query.
  ExtensionResponse getQueryColumns(
    1:string sql,
  ),
}
```
