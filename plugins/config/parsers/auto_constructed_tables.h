/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/config.h>
#include <osquery/core/tables.h>

namespace osquery {
/**
 * @brief A ConfigParserPlugin for ATC (Auto Table Construction)
 */
class ATCPlugin : public TablePlugin {
  TableColumns tc_columns_;
  std::string sqlite_query_;
  std::string path_;

 protected:
  std::string columnDefinition() const {
    return ::osquery::columnDefinition(tc_columns_);
  }

  TableColumns columns() const override {
    return tc_columns_;
  }

 public:
  ATCPlugin(const std::string& path,
            const TableColumns& tc_columns,
            const std::string& sqlite_query)
      : tc_columns_(tc_columns), sqlite_query_(sqlite_query), path_(path) {}

  TableRows generate(QueryContext& context) override;
};

/**
 * @brief A ConfigParserPlugin for ATC (Auto Table Construction)
 */
class ATCConfigParserPlugin : public ConfigParserPlugin {
  const std::string kParserKey{"auto_table_construction"};
  const std::string kDatabaseKeyPrefix{"atc."};

  Status removeATCTables(const std::set<std::string>& tables);
  std::set<std::string> registeredATCTables();

 public:
  std::vector<std::string> keys() const override {
    return {kParserKey};
  }

  Status setUp() override;
  Status update(const std::string& source, const ParserConfig& config) override;
};
} // namespace osquery
