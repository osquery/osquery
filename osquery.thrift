namespace cpp osquery.extensions

/// Registry operations use a registry name, plugin name, request/response.
typedef map<string, string> ExtensionPluginRequest
typedef list<map<string, string>> ExtensionPluginResponse

struct InternalExtensionInfo {
  1:string name,
  2:string version,
  3:string sdk_version,
}

typedef i64 ExtensionRouteUUID
typedef map<string, string> ExtensionRoute
typedef map<string, ExtensionRoute> ExtensionRouteTable
typedef map<string, ExtensionRouteTable> ExtensionRegistry
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
  ExtensionStatus ping(),
  ExtensionResponse call(
    1:string registry,
    2:string item,
    3:ExtensionPluginRequest request),
}

service ExtensionManager extends Extension {
  InternalExtensionList extensions(),
  ExtensionStatus registerExtension(
    1:InternalExtensionInfo info,
    2:ExtensionRegistry registry),
  ExtensionStatus deregisterExtension(
    1:ExtensionRouteUUID uuid,
  ),
}
