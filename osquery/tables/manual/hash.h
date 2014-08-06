// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_TABLES_HASH_H
#define OSQUERY_TABLES_HASH_H

#include "osquery/sqlite3.h"

// Make sure we can call this stuff from C++.
#ifdef __cplusplus
extern "C" {
#endif

// An sqlite3_hash is an abstract type to stores an instance of
// an integer array.
typedef struct sqlite3_hash sqlite3_hash;


// Invoke this routine to create a specific instance of an hash object.
// The new hash object is returned by the 3rd parameter.
//
// Each hash object corresponds to a virtual table in the TEMP table
// with a name of zName.
//
// Destroy the hash object by dropping the virtual table.  If not done
// explicitly by the application, the virtual table will be dropped implicitly
// by the system when the database connection is closed.
int sqlite3_hash_create(
  sqlite3 *db,
  const char *zName,
  sqlite3_hash **ppReturn
);

#ifdef __cplusplus
}  // End of the 'extern "C"' block
#endif

#endif /* OSQUERY_TABLES_HASH_H */
