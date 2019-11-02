

#include <osquery/registry_factory.h>

namespace osquery {

/// External (extensions) SQL implementation plugin provider for "sql" registry.
class ExternalSQLPlugin : public SQLPlugin {
 public:
  Status query(const std::string& query,
               QueryData& results,
               bool use_cache = false) const override;

  Status getQueryTables(const std::string& query,
                        std::vector<std::string>& tables) const override {
    static_cast<void>(query);
    static_cast<void>(tables);
    return Status::success();
  }

  Status getQueryColumns(const std::string& query,
                         TableColumns& columns) const override;
};

/**
 * @brief Create the external SQLite implementation wrapper.
 *
 * Anything built with only libosquery and not the 'additional' library will
 * not include a native SQL implementation. This applies to extensions and
 * separate applications built with the osquery SDK.
 *
 * The ExternalSQLPlugin is a wrapper around the SQLite API, which forwards
 * calls to an osquery extension manager (core).
 */
REGISTER_INTERNAL(ExternalSQLPlugin, "sql", "sql");

Status ExternalSQLPlugin::query(const std::string& query,
                                QueryData& results,
                                bool use_cache) const {
  static_cast<void>(use_cache);
  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(FLAGS_extensions_socket);
  if (!status.ok()) {
    return status;
  }

  try {
    ExtensionManagerClient client(FLAGS_extensions_socket);
    status = client.query(query, results);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  return status;
}

Status ExternalSQLPlugin::getQueryColumns(const std::string& query,
                                          TableColumns& columns) const {
  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(FLAGS_extensions_socket);
  if (!status.ok()) {
    return status;
  }

  QueryData qd;
  try {
    ExtensionManagerClient client(FLAGS_extensions_socket);
    status = client.getQueryColumns(query, qd);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Translate response map: {string: string} to a vector: pair(name, type).
  for (const auto& column : qd) {
    for (const auto& col : column) {
      columns.push_back(std::make_tuple(
          col.first, columnTypeName(col.second), ColumnOptions::DEFAULT));
    }
  }

  return status;
}
} // namespace osquery
