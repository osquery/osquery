// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_TABLES_BASE_H
#define OSQUERY_TABLES_BASE_H

#include "osquery/sqlite3.h"

namespace osquery { namespace tables {

// Our cursor object
struct base_cursor {
  // similarly to sqlite3_vtab, practical implementations will likely subclass
  // this structure to add additional private fields.
  sqlite3_vtab_cursor base;

  // field that will be used to represent the current cursor position
  int row;
};

// Our virtual table object
template <class T_STRUCT>
struct x_vtab {
  // virtual table implementations will normally subclass this structure to add
  // additional private and implementation-specific fields
  sqlite3_vtab base;

  // to get custom functionality, add our own struct as well
  T_STRUCT *pContent;
};


// This method releases a connection to a virtual table, just like the
// xDisconnect method, and it also destroys the underlying table
// implementation. This method undoes the work of xCreate.
template <class T_VTAB>
int xDestroy(sqlite3_vtab *p) {
  T_VTAB *pVtab = (T_VTAB*)p;
  sqlite3_free(pVtab);
  return SQLITE_OK;
}

// Open a new cursor on the base table.
template <class T_CURSOR>
int xOpen(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor) {
  // this will get overwritten if pVtab was successfully allocated. if pVtab
  // wasn't allocated, it means we have no memory
  int rc = SQLITE_NOMEM;

  // declare a value to be used as the virtual table's cursor
  T_CURSOR *pCur;

  // allocate the correct amount of memory for your virtual table cursor
  pCur = new T_CURSOR;

  // if the cursor was successfully allocated
  if(pCur) {
    // overwrite the entire memory that was allocated with zeros
    memset(pCur, 0, sizeof(T_CURSOR));

    // cast the cursor object back to type sqlite3_vtab_cursor and assign it to
    // the address that was supplied by the function call
    *ppCursor = (sqlite3_vtab_cursor *)pCur;

    // if you've gotten this far, everything succeeded so we can set rc, which
    // will be used as our return value, to SQLITE_OK
    rc = SQLITE_OK;
  }

  // return the value we set to rc, which can either be SQLITE_OK or
  // SQLITE_NOMEM
  return rc;
}

// Close a base table cursor.
template <class T_CURSOR>
int xClose(sqlite3_vtab_cursor *cur) {
  // the xClose interface accepts a sqlite3_vtab_cursor. if we need to do
  // something specific to our virtual table to free it, cast it back to
  // your own cursor type
  T_CURSOR *pCur = (T_CURSOR *)cur;

  // finally, free the structure using sqlite's built-in memory allocation
  // function
  // in C, we would use sqlite3_free(pCur);
  delete pCur;

  // return SQLITE_OK because everything succeeded
  return SQLITE_OK;
}

// This is executed when you query a virtual table with a WHERE claue.
static int xBestIndex(
  sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo) {
  return SQLITE_OK;
}

// Advance the cursor to the next row.
template <class T_CURSOR>
int xNext(sqlite3_vtab_cursor *cur) {
  T_CURSOR *pCur = (T_CURSOR *)cur;
  // increment the value of i, so that xColumn knowns what value to return
  pCur->row++;
  return SQLITE_OK;
}

// Determine if the end of the table has been reached
template <class T_CURSOR, class T_VTAB>
int xEof(sqlite3_vtab_cursor *cur) {
  T_CURSOR *pCur = (T_CURSOR *)cur;
  T_VTAB *pVtab = (T_VTAB *)cur->pVtab;
  return pCur->row >= pVtab->pContent->n;
}

// Retrieve the current rowid
template <class T_CURSOR>
int xRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  T_CURSOR *pCur = (T_CURSOR *)cur;
  // return the value of i, which is set to 0 in xFilter and incremented in
  // xNext
  *pRowid = pCur->row;
  return SQLITE_OK;
}

// Table constructor for the base module.
template <class T_VTAB, class T_STRUCT>
int xCreate(
  sqlite3 *db,                     /* Database where module is created */
  void *pAux,                      /* clientdata for the module */
  int argc,                        /* Number of arguments */
  const char *const *argv,         /* Value for all arguments */
  sqlite3_vtab **ppVtab,           /* Write the new virtual table obj here */
  char **pzErr,                    /* Put error message text here */
  const char *createTableStatement /* the vtables create table statement */
) {
  // this will get overwritten if pVtab was successfully allocated. if pVtab
  // wasn't allocated, it means we have no memory
  int rc = SQLITE_NOMEM;

  // allocate the correct amount of memory for your virtual table structure
  T_VTAB *pVtab = new T_VTAB;

  // if the virtual table structure was successfully allocated
  if(pVtab) {
    // overwrite the entire memory that was allocated with zeros
    memset(pVtab, 0, sizeof(T_VTAB));

    // the pAux argument is the copy of the client data pointer that was the
    // fourth argument to the sqlite3_create_module() or
    // sqlite3_create_module_v2() call that registered the virtual table
    // module. This sets the pContent value of the virtual table struct to
    // whatever that value was
    pVtab->pContent = (T_STRUCT*)pAux;

    // this interface is called to declare the format (the names and datatypes
    // of the columns) of the virtual tables they implement
    rc = sqlite3_declare_vtab(
      db,
      createTableStatement
    );
  }
  // cast your virtual table objet back to type sqlite3_vtab and assign it to
  // the address supplied by the function call
  *ppVtab = (sqlite3_vtab *)pVtab;

  // if all went well, sqlite3_declare_vtab will have returned SQLITE_OK and
  // that is what will be returned
  return rc;
}

// Invoke this routine to create a specific instance of an example object.
// The new example object is returned by the 3rd parameter.
//
// Each vtable object corresponds to a virtual table in the TEMP table
// with a name of zName.
//
// Destroy the vtable object by dropping the virtual table.  If not done
// explicitly by the application, the virtual table will be dropped implicitly
// by the system when the database connection is closed.
template <class T_STRUCT>
int sqlite3_attach_vtable(
  sqlite3 *db, const char *zName, const sqlite3_module *module) {
  int rc = SQLITE_OK;
  T_STRUCT *p = new T_STRUCT;

  if (p == 0) {
    return SQLITE_NOMEM;
  }
  memset(p, 0, sizeof(*p));

  rc = sqlite3_create_module(db, zName, module, p);
  if (rc == SQLITE_OK) {
    char *zSql;
    zSql = sqlite3_mprintf("CREATE VIRTUAL TABLE temp.%Q USING %Q",
            zName, zName);
    rc = sqlite3_exec(db, zSql, 0, 0, 0);
    sqlite3_free(zSql);
  }

  return rc;
}

}}

#endif /* OSQUERY_TABLES_BASE_H */
