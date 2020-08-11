/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <asl.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#ifndef ASL_API_VERSION
#define OLD_ASL_API
#endif

namespace osquery {
namespace tables {

#ifdef OLD_ASL_API
inline void asl_release(aslmsg msg) { asl_free(msg); }

inline void asl_release(aslresponse resp) { aslresponse_free(resp); }

inline aslmsg asl_next(aslresponse resp) { return aslresponse_next(resp); }
#endif

/**
 * @brief Add a new operation to the query.
 *
 * All of the operations are logically ANDed when performing the query.
 *
 * @param query The query on which to add the operation
 * @param key Key to match on
 * @param value Value that should match for the key and operation.
 * @param op The (osquery) operator to use. Will be converted to the equivalent
 * ASL operator.
 * @param col_type Type of the column that this operation is performed on.
 */
void addQueryOp(aslmsg& query,
                const std::string& key,
                const std::string& value,
                ConstraintOperator op,
                ColumnType col_type);

/**
 * @brief Create an ASL query object from the QueryContext.
 *
 * @param context QueryContext used to form the query.
 *
 * @return An ASL query object corresponding to the context.
 */
aslmsg createAslQuery(const QueryContext& context);

/**
 * @brief Read a row of ASL data into an osquery Row.
 *
 * @param row The ASL row to read data from.
 * @param r The osquery Row to write data into.
 */
void readAslRow(aslmsg row, Row& r);

/**
 * @brief Convert a LIKE format string into a regex
 *
 * @param like_str The LIKE style string to convert
 *
 * @return A regex corresponding to the input LIKE string
 */
std::string convertLikeRegex(const std::string& like_str);
}
}
