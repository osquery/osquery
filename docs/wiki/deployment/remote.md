# Remotely interfacing osquery

osquery's remote configuration and logger plugins are completely optional. The default built-in plugins receive and report via `https://` URI endpoints. osquery provides somewhat flexible node (the machine running osquery) authentication and identification though an 'enrollment' concept.

The remote settings and plugins are mostly provided as examples. It is best to write custom plugins that implement specific web services or integrations. The remote settings uses a lot of additional [CLI-flags](../installation/cli-flags.md) for configuring the osquery clients, they are mostly organized under the **Remote Settings** heading.

## Remote authentication

The most important differentiator to the **filesystem** suite of plugins is an authentication (and enrollment) step. Machines running `osqueryd` processes are called **nodes** and must authenticate to the remote server for every config retrieval and log submission request.

The initial step is called an "enroll step" and in the case of **tls** plugins, uses an implicit *enroll* plugin, also called **tls**. If you enable either config or logger **tls** plugins the enrollment plugin will turn on automatically. Enrollment provides an initial secret to the remote server in order to negotiate a private node secret used for future identification. The process is simple:

1. Configure a target `--tls_hostname`, `--enroll_tls_endpoint`.
2. Configure a proxy `--proxy_hostname` (Optional Step).
3. Place your server's root certificate authority's PEM-encoded certificate into a file, for example `/path/to/server-root.pem` and configure the client to pin to these roots: `--tls_server_certs=`.
4. Submit an `--enroll_secret_path`, an `--enroll_secret_env`, or use TLS-client authentication, to the enroll endpoint.
5. Receive a **node_key** and store within the node's persistent storage (RocksDB).
6. Make config/logger requests while providing **node_key** as identification/authentication.

The validity of a **node_key** is determined and implemented in the TLS server. The node will request the key during an initial enroll step then post the key during subsequent requests for config or logging.

**Note:** `--proxy_hostname` is used to communicate via proxy server.

### Simple shared secret enrollment

A deployment key, called an enrollment shared secret, is the simplest **tls** plugin enrollment authentication method. A protected shared secret is written to disk and osquery reads then posts the content to `--enroll_tls_endpoint` once during enrollment. The TLS server may implement an enrollment request approval process that requires manual intervention/approval for each new enrollment request.

After enrollment, a node maintains the response **node_key** for authenticated requests to config and logger TLS endpoints.

The shared secret can be stored in a plain-text file which is specified at runtime with the flag `--enroll_secret_path=/path/to/file.ext`.
The shared secret can alternatively be kept in an environment variable which is specified with the flag `--enroll_secret_env=NAME_OF_VARIABLE`.

### TLS client-auth enrollment

If the **node** machines have a deployed TLS client certificate and key, they should include those paths using `--tls_client_cert` and `--tls_client_key`. The TLS server may implement an enroll process to supply nodes with identifying **node_key**s or return blank keys during enrollment and require TLS client authentication for every endpoint request.

If using TLS client authentication the enrollment step can be skipped entirely. Note that it is NOT skipped automatically. If your service does not need/implement enrollment include `--disable_enrollment` in the osquery configuration.

## Remote server API

The most basic TLS-based server should implement 3 HTTP POST endpoints. This API is a simple reference and should be built upon using custom plugins based on the included **tls** plugin suite. Although this API is basic, it is functional using the built-in plugins.

**Enrollment** request POST body:

```json
{
  "enroll_secret": "...", // Optional.
  "host_identifier": "..." // Determined by the --host_identifier flag
  "host_details": { // A dictionary of keys mapping to helpful osquery tables.
    "os_version": {},
    "osquery_info": {},
    "system_info": {},
    "platform_info": {}
  }
}
```

**Enrollment** response POST body:

```json
{
  "node_key": "...", // Optionally blank
  "node_invalid": false // Optional, return true to indicate failure.
}
```

## Remote configuration

**Configuration** request POST body:

```json
{
  "node_key": "..." // Optionally blank
}
```

Configuration responses should be exactly the same JSON/format as read by the **filesystem** config plugin. There is no concept of multiple configuration sources with the provided **tls** plugin. A server should amalgamate/merge several configs itself.

**Configuration** response POST body:

```json
{
  "schedule": {
    "query_name": {
      "query": "...",
      "interval": 10
    }
  },
  "node_invalid": false // Optional, return true to indicate re-enrollment.
}
```

The POSTed logger data is exactly the same as logged to disk by the **filesystem** plugin with an additional important key: `log_type`. The filesystem plugin differentiates log types by writing distinct file names. The **tls** plugin includes: `result` or `status`. Snapshot queries are `result` queries.

## Remote logging

**Logger** request POST body:

```json
{
  "node_key": "...", // Optionally blank
  "log_type": "result", // Either "result" or "status"
  "data": [
    {...} // Each result event, or status event
  ]
}
```

**Logger** response POST body:

```json
{
  "node_invalid": false // Optional, return true to indicate re-enrollment.
}
```

## Distributed queries

As of version 1.5.3, osquery provides support for "ad-hoc" or distributed queries. The concept of running a query outside of the schedule and having results returned immediately. Distributed queries must be explicitly enabled with a [CLI flag](../installation/cli-flags.md) or option, and you must explicitly enable and configure the distributed plugin.

**Distributed read** request POST body:

```json
{
  "node_key": "..." // Optionally blank
}
```

The read request sends the enrollment **node_key** for identification. The distributed plugin should work in concert with the enrollment plugin.

**Distributed read** response POST body:

```json
{
  "queries": {
    "id1": "SELECT * FROM osquery_info;",
    "id2": "SELECT * FROM osquery_schedule;",
    "id3": "SELECT * FROM does_not_exist;"
  },
  "node_invalid": false // Optional, return true to indicate re-enrollment.
}
```

**Distributed write** request POST body:

```json
{
  "node_key": "...",
  "queries": {
    "id1": [
      {"column1": "value1", "column2": "value2"},
      {"column1": "value1", "column2": "value2"}
    ],
    "id2": [
      {"column1": "value1", "column2": "value2"},
      {"column1": "value1", "column2": "value2"}
    ],
    "id3": []
  },
  "statuses": {
    "id1": 0,
    "id2": 0,
    "id3": 2,
  }
}
```

As of osquery version 2.1.2, the distributed write API includes a top-level `statuses` key. These error codes correspond to SQLite error codes. Consider non-0 values to indicate query execution failures.

**Distributed write** response POST body:

```json
{
  "node_invalid": false // Optional, return true to indicate re-enrollment.
}
```

## Customizations

There are several unlisted flags to further control the remote settings. These controls are helpful if using a somewhat opaque API.

`--tls_secret_always=True` will always send the enrollment secret. This will not perform an enrollment request with every config/logger attempt but rather "also" include the secret. If this is enabled, the secret is appended as a URI variable.

`--tls_enroll_override=enroll_secret` this allows one to rename the enrollment key request body or URI variable.

## Remote logging buffering

In most cases the client plugins default to "3-strikes-you're-out" when attempting to `HTTP GET`/`HTTP POST` to the configured endpoints. If a configuration cannot be retrieved the client will exit non-0 but a non-responsive logger endpoint will cause logs to buffer in RocksDB. The logging buffer size can be controlled by a [CLI flag](../installation/cli-flags.md), and if the size overflows the logs will drop.

The TLS client does not handle HTTP errors, if the service returns a bad request or otherwise an indicator of overflowed length, the request will fail. The default max size of values combined with the maximum number of log events to send per request are sane and should not overflow default HTTP server maximum request limits.

## Server testing

We include a very basic example python TLS/HTTPS server: [./tools/tests/test_http_server.py](https://github.com/osquery/osquery/blob/master/tools/tests/test_http_server.py). And a set of unit/integration tests: [./osquery/remote/transports/tests/tls_transports_tests.cpp](https://github.com/osquery/osquery/blob/master/osquery/remote/transports/tests/tls_transports_tests.cpp) for a reference server implementation.

The TLS clients built into osquery are implemented in its own `http_client`, built on top of Boost.Beast ASIO header-library and a statically linked copy of OpenSSL (does not use a system OpenSSL library, even if present).

The osquery TLS client implementation supports only TLS protocol v1.2, and intentionally no longer supports the deprecated TLS 1.1/1.0, as of osquery v4.7.0. The following cipher suites are supported by the TLS client (see `/osquery/remote/transports/tls.h`):

```text
ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:\
DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:\
!aNULL:!MD5:!CBC:!SHA
```

Additionally, the osquery TLS clients use a `osquery/X.Y.Z` UserAgent, where "X.Y.Z" is the client build version.

## Example projects

[Doorman](https://github.com/mwielgoszewski/doorman) is a project that implements the TLS remote settings API. Doorman uses "tags", which can be applied to nodes, packs, and queries, in order to dynamically generate configurations for a unique set or all nodes being managed. Doorman also supports the distributed read and write API, allowing an administrator to schedule ad-hoc queries to be run immediately or in the future.

[Zentral](https://github.com/zentralopensource/zentral) is a Framework and Django based web server, which implements the TLS remote settings API. Zentral will dynamically generate configurations in "probes", these can contain packs and single queries. Probes process events with input filters (added, removed, "tags", etc.), optionally trigger output actions, and notifications for results returned. Scope for "probes" is available for all devices, business units, and "tagged" device groups, sharding for "probes" is available for scopes. Zentral also supports the distributed read and write API to schedule ad-hoc queries.

## Remote settings testing

The most basic example of a server implementing the remote settings API is the [./tools/tests/test_http_server.py](https://github.com/osquery/osquery/blob/master/tools/tests/test_http_server.py) example script. Let's start this server and have `osqueryd` exercise the API:

```shell
$ ./tools/tests/test_http_server.py -h
usage: test_http_server.py [-h] [--tls] [--persist] [--timeout TIMEOUT]
                           [--cert CERT_FILE] [--key PRIVATE_KEY_FILE]
                           [--ca CA_FILE] [--use_enroll_secret]
                           [--enroll_secret SECRET_FILE]
                           PORT

osquery python https server for client TLS testing.

positional arguments:
  PORT                  Bind to which local TCP port.

optional arguments:
  -h, --help            show this help message and exit
  --tls                 Wrap the HTTP server socket in TLS.
  --persist             Wrap the HTTP server socket in TLS.
  --timeout TIMEOUT     If not persisting, exit after a number of seconds
  --cert CERT_FILE      TLS server cert.
  --key PRIVATE_KEY_FILE
                        TLS server cert private key.
  --ca CA_FILE          TLS server CA list for client-auth.
  --use_enroll_secret   Require an enrollment secret for node enrollment
  --enroll_secret SECRET_FILE
                        File containing enrollment secret
$ ./tools/tests/test_http_server.py --tls --persist --cert ./tools/tests/configs/test_server.pem --key ./tools/tests/configs/test_server.key --ca .tools/tests/configs/test_server_ca.pem --use_enroll_secret --enroll_secret ./tools/tests/test_enroll_secret.txt 8080
-- [DEBUG] Starting TLS/HTTPS server on TCP port: 8080
```

This starts a HTTPS server bound to port 8080 using some fake CA/server cert and an example shared enrollment key from the text file **./tools/tests/test_enroll_secret.txt**. If you inspect the file, see that the enrollment secret is **this_is_a_deployment_secret**. The server's enroll step will expect osquery clients to submit this secret.

We will use an `osqueryd` client and set the required TLS settings. When enforcing TLS server authentication, note that the example server is using a toy certificate with the subject: `C=US, ST=California, O=osquery-testing, CN=localhost`:

```shell
$ osqueryd --verbose --ephemeral --disable_database \
    --tls_hostname localhost:8080 \
    --tls_server_certs ./tools/tests/test_server_ca.pem \
    --config_plugin tls \
    --config_tls_endpoint /config \
    --logger_tls_endpoint /logger \
    --logger_plugin tls  \
    --enroll_tls_endpoint /enroll \
    --enroll_secret_path ./tools/tests/test_enroll_secret.txt
```

There are a LOT of command line switches here! The basics notes are (1) set the TLS hostname and port, note that no `https://` is used, as well as the explicit set of certificates to expect; (2) set the plugin options for the config and logger; (3) set the plugin options for enrollment. Turning `verbose` mode on helps describe the expected behavior.

```text
I1015 10:36:06.894544 2032685056 init.cpp:263] osquery initialized [version=1.5.3]
I1015 10:36:06.935755 2032685056 tls.cpp:68] TLSEnrollPlugin requesting a node enroll key from: https://localhost:8080/enroll
I1015 10:36:06.936123 2032685056 tls.cpp:196] TLS/HTTPS POST request to URI: https://localhost:8080/enroll
I1015 10:36:06.947465 2032685056 tls.cpp:196] TLS/HTTPS POST request to URI: https://localhost:8080/config
I1015 10:36:10.288635 3825664 scheduler.cpp:56] Executing query: SELECT * FROM processes;
I1015 10:36:10.366140 3825664 scheduler.cpp:101] Found results for query (tls_proc) for host: YOURHOSTNAME.local
I1015 10:36:11.019227 528384 tls.cpp:196] TLS/HTTPS POST request to URI: https://localhost:8080/logger
[...]
```

And the example TLS server will show something similar:

```text
127.0.0.1 - - [15/Oct/2015 10:36:06] "POST /enroll HTTP/1.1" 200 -
-- [DEBUG] Request: {u'enroll_secret': u'this_is_a_deployment_secret', u'host_identifier': u'YOURHOSTNAME.local'}
-- [DEBUG] Replying: {u'node_key': u'this_is_a_node_secret'}
127.0.0.1 - - [15/Oct/2015 10:36:06] "POST /config HTTP/1.1" 200 -
-- [DEBUG] Request: {u'node_key': u'this_is_a_node_secret'}
-- [DEBUG] Replying: {u'schedule': {u'tls_proc': {u'query': u'select * from processes', u'interval': 1}}}
127.0.0.1 - - [15/Oct/2015 10:36:11] "POST /logger HTTP/1.1" 200 -
-- [DEBUG] Request: {u'node_key': u'this_is_a_node_secret', u'data': [...]}
[...]
```
