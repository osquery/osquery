// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/tables/manual/filesystem.h"

#include <string>
#include <vector>
#include <iostream>
#include <cstring>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

namespace fs = boost::filesystem;

/*
** Definition of the sqlite3_filesystem object.
**
** The internal representation of an filesystem object is subject
** to change, is not externally visible, and should be used by
** the implementation of filesystem only.  This object is opaque
** to users.
*/
struct sqlite3_filesystem {
  int n; /* number of elements */
  std::vector<std::string> path; /* the full path of a filesystem object */
  std::vector<bool> is_file; /* if the filesystem object is a file */
  std::vector<bool> is_dir; /* if the filesystem object is a directory */
  std::vector<bool> is_link; /* if the filesystem object is a symlink */
};

/*
 * Objects used internally by the virtual table implementation
 *
 * we write "typedef struct x x" here so that we can write "x" later instead of
 * "stuct x"
**/
typedef struct filesystem_vtab filesystem_vtab;
typedef struct filesystem_cursor filesystem_cursor;

/*
 * Our virtual table object
**/
struct filesystem_vtab {
  // virtual table implementations will normally subclass this structure to add
  // additional private and implementation-specific fields
  sqlite3_vtab base;

  // to get custom functionality, add our own struct as well
  sqlite3_filesystem *pContent;
};

/*
 * Our cursor object
**/
struct filesystem_cursor {
  // similarly to sqlite3_vtab, practical implementations will likely subclass
  // this structure to add additional private fields.
  sqlite3_vtab_cursor base;

  // field that will be used to represent the current cursor position
  int row;
  // the path that is being queried
  std::string path;
};

/*
** Free an sqlite3_filesystem object.
*/
static void filesystemFree(sqlite3_filesystem *p) { sqlite3_free(p); }

/*
 * This method releases a connection to a virtual table, just like the
 * xDisconnect method, and it also destroys the underlying table
 * implementation. This method undoes the work of xCreate.
*/
static int filesystemDestroy(sqlite3_vtab *p) {
  filesystem_vtab *pVtab = (filesystem_vtab *)p;
  sqlite3_free(pVtab);
  return SQLITE_OK;
}

/*
** Table constructor for the filesystem module.
*/
static int filesystemCreate(
    sqlite3 *db, /* Database where module is created */
    void *pAux, /* clientdata for the module */
    int argc, /* Number of arguments */
    const char *const *argv, /* Value for all arguments */
    sqlite3_vtab **ppVtab, /* Write the new virtual table object here */
    char **pzErr /* Put error message text here */
    ) {
  // this will get overwritten if pVtab was successfully allocated. if pVtab
  // wasn't allocated, it means we have no memory
  int rc = SQLITE_NOMEM;

  // allocate the correct amount of memory for your virtual table structure
  // filesystem_vtab *pVtab = sqlite3_malloc(sizeof(filesystem_vtab));
  filesystem_vtab *pVtab = new filesystem_vtab;

  // if the virtual table structure was successfully allocated
  if (pVtab) {
    // overwrite the entire memory that was allocated with zeros
    memset(pVtab, 0, sizeof(filesystem_vtab));

    // the pAux argument is the copy of the client data pointer that was the
    // fourth argument to the sqlite3_create_module() or
    // sqlite3_create_module_v2() call that registered the virtual table
    // module. This sets the pContent value of the virtual table struct to
    // whatever that value was
    pVtab->pContent = (sqlite3_filesystem *)pAux;

    // this interface is called to declare the format (the names and datatypes
    // of the columns) of the virtual tables they implement
    const char *create_table_statement =
        "CREATE TABLE fs("
        "path VARCHAR, "
        "filename VARCHAR, "
        "is_file INTEGER, "
        "is_dir INTEGER, "
        "is_link INTEGER"
        ")";
    rc = sqlite3_declare_vtab(db, create_table_statement);
  }
  // cast your virtual table objet back to type sqlite3_vtab and assign it to
  // the address supplied by the function call
  *ppVtab = (sqlite3_vtab *)pVtab;

  // if all went well, sqlite3_declare_vtab will have returned SQLITE_OK and
  // that is what will be returned
  return rc;
}

/*
** Open a new cursor on the filesystem table.
*/
static int filesystemOpen(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor) {
  // this will get overwritten if pVtab was successfully allocated. if pVtab
  // wasn't allocated, it means we have no memory
  int rc = SQLITE_NOMEM;

  // declare a value to be used as the virtual table's cursor
  filesystem_cursor *pCur;

  // allocate the correct amount of memory for your virtual table cursor
  // pCur = sqlite3_malloc(sizeof(filesystem_cursor));
  pCur = new filesystem_cursor;

  // if the cursor was successfully allocated
  if (pCur) {
    // overwrite the entire memory that was allocated with zeros
    memset(pCur, 0, sizeof(filesystem_cursor));

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

/*
** Close a filesystem table cursor.
*/
static int filesystemClose(sqlite3_vtab_cursor *cur) {
  // the xClose interface accepts a sqlite3_vtab_cursor. if we need to do
  // something specific to our virtual table to free it, cast it back to
  // your own cursor type
  filesystem_cursor *pCur = (filesystem_cursor *)cur;

  // finally, free the structure using sqlite's built-in memory allocation
  // function
  // in C, we would use sqlite3_free(pCur);
  delete pCur;

  // return SQLITE_OK because everything succeeded
  return SQLITE_OK;
}

/*
** Retrieve a column of data.
*/
static int filesystemColumn(sqlite3_vtab_cursor *cur,
                            sqlite3_context *ctx,
                            int col) {
  filesystem_cursor *pCur = (filesystem_cursor *)cur;
  filesystem_vtab *pVtab = (filesystem_vtab *)cur->pVtab;

  // return a specific column from a specific row, depending on the state of
  // the cursor
  if (pCur->row >= 0 && pCur->row < pVtab->pContent->n) {
    switch (col) {
    // path
    case 0:
      sqlite3_result_text(ctx, (pCur->path).c_str(), -1, nullptr);
      break;
    // filename
    case 1:
      sqlite3_result_text(
          ctx, (pVtab->pContent->path[pCur->row]).c_str(), -1, nullptr);
      break;
    // is_file
    case 2:
      sqlite3_result_int(ctx, (int)pVtab->pContent->is_file[pCur->row]);
      break;
    // is_dir
    case 3:
      sqlite3_result_int(ctx, (int)pVtab->pContent->is_dir[pCur->row]);
      break;
    // is_link
    case 4:
      sqlite3_result_int(ctx, (int)pVtab->pContent->is_link[pCur->row]);
      break;
    }
  }
  return SQLITE_OK;
}

/*
** Retrieve the current rowid.
*/
static int filesystemRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  filesystem_cursor *pCur = (filesystem_cursor *)cur;
  // return the value of i, which is set to 0 in xFilter and incremented in
  // xNext
  *pRowid = pCur->row;
  return SQLITE_OK;
}

static int filesystemEof(sqlite3_vtab_cursor *cur) {
  filesystem_cursor *pCur = (filesystem_cursor *)cur;
  filesystem_vtab *pVtab = (filesystem_vtab *)cur->pVtab;
  return pCur->row >= pVtab->pContent->n;
}

/*
** Advance the cursor to the next row.
*/
static int filesystemNext(sqlite3_vtab_cursor *cur) {
  filesystem_cursor *pCur = (filesystem_cursor *)cur;
  // increment the value of i, so that xColumn knowns what value to return
  pCur->row++;
  return SQLITE_OK;
}

/*
 * This function resets the cursor for a new query. From the documentation:
 *
 * This method begins a search of a virtual table. The first argument is a
 * cursor opened by xOpen. The next two arguments define a particular search
 * index previously chosen by xBestIndex. The specific meanings of idxNum and
 * idxStr are unimportant as long as xFilter and xBestIndex agree on what that
 * meaning is.
 *
 * This method must return SQLITE_OK if successful, or an sqlite error code if
 * an error occurs.
**/
static int filesystemFilter(sqlite3_vtab_cursor *pVtabCursor,
                            int idxNum,
                            const char *idxStr,
                            int argc,
                            sqlite3_value **argv) {
  // you need to operate on the sqlite3_vtab_cursor object as your own
  // virtual table's cursor type, so cast it back to x_cursor
  filesystem_cursor *pCur = (filesystem_cursor *)pVtabCursor;
  filesystem_vtab *pVtab = (filesystem_vtab *)pVtabCursor->pVtab;

  // reset the count value of your cursor's structure
  pCur->row = 0;

  // the filesystem table requires you to have a where clause to specify the
  // path. if argc is 0, then no values were specified as valid constraints in
  // xBestIndex. there's currently logic in xBestIndex to prevent execution
  // from getting this far if that were to happen, but we check argc here as
  // well to illustrate the requirement
  if (argc <= 0) {
    return SQLITE_MISUSE;
  }

  // extract the RHS value for the path constraint into the cursor's path field
  pCur->path = std::string((const char *)sqlite3_value_text(argv[0]));

  // if the path doesn't exist, return early
  if (!fs::exists(pCur->path)) {
    std::cerr << pCur->path << " doesn't exist" << std::endl;
    return SQLITE_OK;
  }

  // iterate through the directory that is being queried upon and gether the
  // information needed to complete a table scan
  fs::directory_iterator end_iter;
  for (fs::directory_iterator dir_itr(pCur->path); dir_itr != end_iter;
       ++dir_itr) {
    pVtab->pContent->path.push_back(dir_itr->path().string());
    pVtab->pContent->is_file.push_back(fs::is_regular_file(dir_itr->status()));
    pVtab->pContent->is_dir.push_back(fs::is_directory(dir_itr->status()));
    pVtab->pContent->is_link.push_back(fs::is_symlink(dir_itr->status()));
  }

  // set the size of the table based on the amount of results that were queried
  pVtab->pContent->n = pVtab->pContent->path.size();

  // return SQLITE_OK because everything went as planned
  return SQLITE_OK;
}

/*
 * This is executed when you query a virtual table with a WHERE claue. From
 * the documentation:
 *
 * SQLite calls this method when it is running sqlite3_prepare() or the
 * equivalent. By calling this method, the SQLite core is saying to the virtual
 * table that it needs to access some subset of the rows in the virtual table
 * and it wants to know the most efficient way to do that access. The xBestIndex
 * method replies with information that the SQLite core can then use to conduct
 * an efficient search of the virtual table.
**/
static int filesystemBestIndex(sqlite3_vtab *tab,
                               sqlite3_index_info *pIdxInfo) {
  filesystem_vtab *pVtab = (filesystem_vtab *)tab;

  if (pIdxInfo->nConstraint == 0) {
    // the filesystem table requires you to have a where clause to specify the
    // path. if nConstrain is 0, then there were no where clauses.
    goto fail;
  }

  // iterate through all of the constraints (aka where clauses) and look for
  // the constraint on the "path" column
  for (int i = 0; i < pIdxInfo->nConstraint; i++) {
    if (pIdxInfo->aConstraint[i].iColumn == 0 &&
        pIdxInfo->aConstraint[i].usable) {
      pIdxInfo->aConstraintUsage[i].argvIndex =
          pIdxInfo->aConstraint[i].iColumn + 1;
      goto finish;
    }
  }

  // if the code has gotten this far, it means that there were constrains in
  // the query, but none of them were for the path column, which is required
  goto fail;

finish:
  return SQLITE_OK;

fail:
  return SQLITE_MISUSE;
}

/*
** A virtual table module that merely echos method calls into TCL
** variables.
*/
static sqlite3_module filesystemModule = {
    0, /* iVersion */
    filesystemCreate, /* xCreate - create a new virtual table */
    filesystemCreate, /* xConnect - connect to an existing vtab */
    filesystemBestIndex, /* xBestIndex - find the best query index */
    filesystemDestroy, /* xDisconnect - disconnect a vtab */
    filesystemDestroy, /* xDestroy - destroy a vtab */
    filesystemOpen, /* xOpen - open a cursor */
    filesystemClose, /* xClose - close a cursor */
    filesystemFilter, /* xFilter - configure scan constraints */
    filesystemNext, /* xNext - advance a cursor */
    filesystemEof, /* xEof */
    filesystemColumn, /* xColumn - read data */
    filesystemRowid, /* xRowid - read data */
    0, /* xUpdate */
    0, /* xBegin */
    0, /* xSync */
    0, /* xCommit */
    0, /* xRollback */
    0, /* xFindMethod */
    0, /* xRename */
};

/*
** Invoke this routine to create a specific instance of an filesystem object.
** The new filesystem object is returned by the 3rd parameter.
**
** Each filesystem object corresponds to a virtual table in the TEMP table
** with a name of zName.
**
** Destroy the filesystem object by dropping the virtual table.  If not done
** explicitly by the application, the virtual table will be dropped implicitly
** by the system when the database connection is closed.
*/
int sqlite3_filesystem_create(sqlite3 *db,
                              const char *zName,
                              sqlite3_filesystem **ppReturn) {
  int rc = SQLITE_OK;
  sqlite3_filesystem *p;

  *ppReturn = p = new sqlite3_filesystem;

  if (p == 0) {
    return SQLITE_NOMEM;
  }
  memset(p, 0, sizeof(*p));

  rc = sqlite3_create_module_v2(
      db, zName, &filesystemModule, p, (void (*)(void *))filesystemFree);
  if (rc == SQLITE_OK) {
    char *zSql;
    zSql =
        sqlite3_mprintf("CREATE VIRTUAL TABLE temp.%Q USING %Q", zName, zName);
    rc = sqlite3_exec(db, zSql, 0, 0, 0);
    sqlite3_free(zSql);
  }

  return rc;
}
