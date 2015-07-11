osquery's remote configuration and logging plugins are completely optional. The only built-in optional plugins are **tls**. They very simply, receive and report via **https://** URI endpoints. osquery provides somewhat flexible node (the machine running osquery) authentication and identification though an 'enrollment' concept.

The remote settings and plugins are mostly provided as examples. It is best to write custom plugins that implement specific web services or integrations.

## Remote authentication

The most important differentiator to the **filesystem** suite of plugins is an authentication (and enrollment) step. Machines running osqueryd processes are called **nodes** and must authenticate to the remote server for every config retrieval and log submission request.

The initial step is called an "enroll step" and in the case of **tls** plugins, uses an implicit *enroll* plugin, also called **tls**. If you enable either config or logger **tls** plugins the enrollment plugin will turn on automatically. Enrollment provides an initial secret to the remote server in order to negotiate a private node secret used for future identification. The process is simple:

1. Configure a target `tls_hostname`, `enroll_tls_endpoint`.
2. Submit either a `enroll_secret_path`, or use TLS-client authentication, to the enroll endpoint.
3. Receive a `node_key` and store within RocksDB.
4. Make config/logger requests while providing `node_key` as identification/authentication.

The validity of a `node_key` is determined and implemented in the TLS server. The client only manages to ask for the content during enroll, and posts the content during subsequent requests.

### Simple shared secret enrollment

A deployment key, called an enrollment shared secret, is the simplest **tls** plugin enrollment authentication method. A protected shared secret is written to disk and osquery reads then posts the content to `enroll_tls_endpoint` once during enrollment. The TLS server may implement an enrollment request approval process that requires manual intervention/approval for each new enrollment request. 

After enrollment a client maintains the response `node_key` for authenticated requests to config and logger TLS endpoints.

### TLS client-auth enrollment

If the **node** machines have a deployed TLS client certificate and key they should include those paths using `tls_client_cert` and `tls_client_key`. The TLS server may implement an enroll process to supply **nodes** with identifying `node_key`s or return blank keys during enrollment and require TLS client authentication for every endpoint request.

## Remote server API

The most basic TLS-based server should implement 3 HTTP POST endpoints. This API is a simple reference and should be built upon using custom plugins based on the included **tls** plugin suite. Although this API is basic, it is functional using the built-in plugins.

**Enrollment** request POST body:
```json
{
    "enroll_secret": "..." // Optional.
}
```

**Enrollment** response POST body:
```json
{
    "node_key": "...", // Optionally blank
    "node_invalid": false // Optional, return true to indicate failure.
}
```

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
        "query_name": {"query": "...", "interval": 10}
    }
}
```

The posted logger data is exactly the same as logged to disk by the **filesystem** plugin with an additional important key: `log_type`. The filesystem plugin differentiates log types by writing distinct file names. The **tls** plugin includes: "result" or "status". Snapshot queries are "result" queries.

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
```
{}
```

## Remote logging buffering

In most cases the client plugins default to 3-strikes-you're-out when attempting to POST to the configured endpoints. If a configuration cannot be retrieved the client will exit non-0 but a non-responsive logger endpoint will cause logs to buffer in RocksDB. The logging buffer size can be controlled by a [CLI flag](../installation/cli-flags.md), and if the size overflows logs will drop.

## Server testing

We include a very basic example python TLS/HTTPS server: [./tools/tests/test_http_server.py](https://github.com/facebook/osquery/blob/master/tools/tests/test_http_server.py). And a set of unit/integration tests: [./osquery/remote/transports/tests/tls_transports_tests.cpp](https://github.com/facebook/osquery/blob/master/osquery/remote/transports/tests/tls_transports_tests.cpp) for a reference server implementation.

The TLS clients built into osquery use the system-provided OpenSSL libraries. The clients use boost's ASIO header-libraries through the [cpp-netlib](http://cpp-netlib.org/) HTTPS library. OpenSSL is very outdated on OS X (deprecated since OS X 10.7), but still salvageable. 

On Linux and FreeBSD the TLS client prefers the TLS 1.2 protocol, but includes TLS 1.1/1.0 as well as the following cipher suites:

```
ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:\
DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:\
!aNULL:!MD5:!CBC:!SHA
```

On OS X, the client only includes a TLS 1.0 protocol and allows `CBC:SHA` algorithms within cipher suites. 

Additionally, the osquery TLS clients use a `osquery/X.Y.Z` UserAgent, where "X.Y.Z" is the client build version.

