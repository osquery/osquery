osquery supports proprietary tables, config plugins, and logger plugins built in C++ (or languages other than C++) through a Thrift-based extensions API. This is helpful if your enterprise or integration uses an internal method for configuration or log collection. You can internally develop and maintain these custom behaviors in an extension, and ask osquery to depend on the plugins it exposes. To make deployment and management of extensions simpler, osqueryd may "autoload", or subprocess, these extension binaries and monitor their performance.

If you are interested in writing extensions, please read the [SDK and Extensions](../development/osquery-sdk.md) development article. That wiki article describes the Thrift API and provides example C++ code for an extension. Every extension runs as a separate process and communicates to the main osquery process using Thrift and a UNIX domain socket. A single extension may contain an arbitrary number of plugins, and each are registered using a setUp API call. At Facebook, we deploy an `fb-osquery` package and a single extension binary that contains our Facebook-specific tables and internal configuration/logging APIs. 

## Autoloading Extensions

The following [CLI flags](../installation/cli-flags.md) control extension auto-loading:

```sh
--extensions_autoload=/etc/osquery/extensions.load
--extensions_timeout=3
--extensions_interval=3
```

`extensions_autoload` points to a line-delimited set of paths to executables. When osquery launches, each path is evaluated for "safe permissions" (extension executable files must be owned by root or Administrator) and executed as a monitored child process. Each executable receives 3 argument switches: `socket`, `timeout`, `interval`. An extension process may use these to find the osquery process's Thrift socket, as well as hints on retry/backoff configuration if any latency or errors occur. If the `--verbose` flag is passed to osqueryd, the flag will also be received by the executable.

The simplest `extensions.load` file contains a single extension path:

```sh
$ cat /etc/osquery/extensions.load
/usr/lib/osquery/extensions/fb_osquery.ext
$ file /usr/lib/osquery/extensions/fb_osquery.ext
/usr/lib/osquery/extensions/fb_osquery.ext: ELF 64-bit LSB executable
```

The *autoload* workflow is similar to:

- Check if extensions are enabled.
- Read `--extensions_autoload` and check permissions/ownership of each path.
- Checks if the file name extension of the path is .ext. Filename extension must be .ext.
- Fork and execute each path with the switches described above.
- Treat each child process as a "worker" and enforce sane memory/cycle usage.
- Read set config plugin from `--config_plugin`.
- If the config plugin does not exist and at least 1 extension was autoload:
- Wait `--extensions_timeout * --extensions_interval` for the extension to register the config plugin.
- Fail if the plugin is not registered or the plugin returns a failed status.

The same dependency check is applied to the logger plugin setting after a valid config is read. Every registered plugin is available throughout the run of the shell or daemon. 

## Manually Loading Extensions

Extensions can also be loaded individually on the osquery command line, for example:

```sh
$ osqueryi --extension /path/to/your_extension.ext
```

## More Options

Extensions are most useful when used to expose config or logger plugins. Along with auto-loading extensions, you can start daemon services with non-default plugins using `--flagfile=PATH`. The `osqueryd` initscript or SystemV service on Linux searches for a `/etc/osquery/osquery.flags` path containing flags. This is a great place to add non-default extensions options or for replacing plugins:

```sh
$ cat /etc/osquery/osquery.flags
--config_plugin=custom_plugin
--logger_plugin=scribe
```

## Troubleshooting

* Ensure that your osquery config has `--disable_extensions=false`, which ought to be the default value.
* If you encounter the following error, you need change the owner of the `your_extension.ext` file to be the root account, or else run osquery with the `--allow_unsafe` flag (not recommended): `watcher.cpp:535] [Ref #1382] Extension binary has unsafe permissions:1`
