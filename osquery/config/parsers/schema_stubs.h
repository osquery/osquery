/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <string>
#include <vector>

#include <osquery/config.h>
#include <osquery/sql.h>

#define SCHEMA_STUBS_ALIAS_DELIMITER "|"
#define SCHEMA_STUBS_COLUMN_DETAIL_DELIMITER "/"

namespace osquery {

void SchemaStubsParseTypeAndOptions(std::string str,
                                    ColumnType& columnType,
                                    ColumnOptions& opts);

std::string SchemaStubsParseColumnName(std::string str,
                                       ColumnType& columnType,
                                       ColumnOptions& opts);

std::string SchemaStubsParseTableName(std::string str,
                                      std::vector<std::string>& aliases);

} // namespace osquery
