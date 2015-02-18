namespace cpp osquery.extensions

/// Registry operations use a registry name, plugin name, request/response.
typedef map<string, string> ExtensionPluginRequest
typedef list<map<string, string>> ExtensionPluginResponse

/// When communicating extension metadata, use a thrift-internal structure.
struct InternalExtensionInfo {
  1:string name,
  2:string version,
  3:string sdk_version,
}

/// Unique ID for each extension.
typedef i64 ExtensionRouteUUID
/// An optional key/value pair provided by extension plugins.
typedef map<string, string> ExtensionRoute
/// A map from each plugin name to its optional route information.
typedef map<string, ExtensionRoute> ExtensionRouteTable
/// A map from each registry name.
typedef map<string, ExtensionRouteTable> ExtensionRegistry
/// A map from each extension's unique ID to its map of registries.
typedef map<ExtensionRouteUUID, InternalExtensionInfo> InternalExtensionList

enum ExtensionCode {
  EXT_SUCCESS = 0,
  EXT_FAILED = 1,
  EXT_FATAL = 2,
}

/// Most communication uses the Status return type.
struct ExtensionStatus {
  1:i32 code,
  2:string message,
  /// Add a thrift Status parameter identifying the request/response.
  3:ExtensionRouteUUID uuid,
}

struct ExtensionResponse {
  1:ExtensionStatus status,
  2:ExtensionPluginResponse response,
}

exception ExtensionException {
  1:i32 code,
  2:string message,
  3:ExtensionRouteUUID uuid,
}

service Extension {
  /// Ping to/from an extension and extension manager for metadata.
  ExtensionStatus ping(),
  /// Call an extension (or core) registry plugin.
  ExtensionResponse call(
    /// The registry name (e.g., config, logger, table, etc).
    1:string registry,
    /// The registry item name (plugin name).
    2:string item,
    /// The thrift-equivilent of an osquery::PluginRequest.
    3:ExtensionPluginRequest request),
}

/// The extension manager is run by the osquery core process.
service ExtensionManager extends Extension {
  /// Return the list of active registered extensions.
  InternalExtensionList extensions(),
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
}
