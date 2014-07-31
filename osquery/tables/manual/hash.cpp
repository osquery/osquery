// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/tables/hash.h"
#include "osquery/core/md5.h"

#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <sstream>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

namespace fs = boost::filesystem;

/*
** Definition of the sqlite3_hash object.
**
** The internal representation of an hash object is subject
** to change, is not externally visible, and should be used by
** the implementation of hash only.  This object is opaque
** to users.
*/
struct sqlite3_hash {
  int n;                          /* number of elements */
  std::vector<std::string> filename;  /* the full path of a hash object */
  std::vector<std::string> md5;  /* the hash of the file at the path */
};

/*
 * Objects used internally by the virtual table implementation
 *
 * we write "typedef struct x x" here so that we can write "x" later instead of
 * "stuct x"
**/
typedef struct hash_vtab hash_vtab;
typedef struct hash_cursor hash_cursor;

/*
 * Our virtual table object
**/
struct hash_vtab {
  // virtual table implementations will normally subclass this structure to add
  // additional private and implementation-specific fields
  sqlite3_vtab base;

  // to get custom functionality, add our own struct as well
  sqlite3_hash *pContent;
};

/*
 * Our cursor object
**/
struct hash_cursor {
  // similarly to sqlite3_vtab, practical implementations will likely subclass
  // this structure to add additional private fields.
  sqlite3_vtab_cursor base;

  // field that will be used to represent the current cursor position
  int row;
  // the path that is being queried
  std::string path;
};

/*
** Free an sqlite3_hash object.
*/
static void hashFree(sqlite3_hash *p) {
  sqlite3_free(p);
}

/*
 * This method releases a connection to a virtual table, just like the
 * xDisconnect method, and it also destroys the underlying table
 * implementation. This method undoes the work of xCreate.
*/
static int hashDestroy(sqlite3_vtab *p) {
  hash_vtab *pVtab = (hash_vtab*)p;
  sqlite3_free(pVtab);
  return SQLITE_OK;
}

/*
** Table constructor for the hash module.
*/
static int hashCreate(
  sqlite3 *db,              /* Database where module is created */
  void *pAux,               /* clientdata for the module */
  int argc,                 /* Number of arguments */
  const char *const *argv,   /* Value for all arguments */
  sqlite3_vtab **ppVtab,    /* Write the new virtual table object here */
  char **pzErr              /* Put error message text here */
) {
  // this will get overwritten if pVtab was successfully allocated. if pVtab
  // wasn't allocated, it means we have no memory
  int rc = SQLITE_NOMEM;

  // allocate the correct amount of memory for your virtual table structure
  // hash_vtab *pVtab = sqlite3_malloc(sizeof(hash_vtab));
  hash_vtab *pVtab = new hash_vtab;

  // if the virtual table structure was successfully allocated
  if(pVtab) {
    // overwrite the entire memory that was allocated with zeros
    memset(pVtab, 0, sizeof(hash_vtab));

    // the pAux argument is the copy of the client data pointer that was the
    // fourth argument to the sqlite3_create_module() or
    // sqlite3_create_module_v2() call that registered the virtual table
    // module. This sets the pContent value of the virtual table struct to
    // whatever that value was
    pVtab->pContent = (sqlite3_hash*)pAux;

    // this interface is called to declare the format (the names and datatypes
    // of the columns) of the virtual tables they implement
    const char *create_table_statement =
      "CREATE TABLE hash("
        "path VARCHAR, "
        "filename VARCHAR, "
        "md5 VARCHAR"
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
** Open a new cursor on the hash table.
*/
static int hashOpen(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor) {
  // this will get overwritten if pVtab was successfully allocated. if pVtab
  // wasn't allocated, it means we have no memory
  int rc = SQLITE_NOMEM;

  // declare a value to be used as the virtual table's cursor
  hash_cursor *pCur;

  // allocate the correct amount of memory for your virtual table cursor
  //pCur = sqlite3_malloc(sizeof(hash_cursor));
  pCur = new hash_cursor;

  // if the cursor was successfully allocated
  if(pCur) {
    // overwrite the entire memory that was allocated with zeros
    memset(pCur, 0, sizeof(hash_cursor));

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
** Close a hash table cursor.
*/
static int hashClose(sqlite3_vtab_cursor *cur) {
  // the xClose interface accepts a sqlite3_vtab_cursor. if we need to do
  // something specific to our virtual table to free it, cast it back to
  // your own cursor type
  hash_cursor *pCur = (hash_cursor *)cur;

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
static int hashColumn(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
) {
  hash_cursor *pCur = (hash_cursor*)cur;
  hash_vtab *pVtab = (hash_vtab*)cur->pVtab;

  // return a specific column from a specific row, depending on the state of
  // the cursor
  if(pCur->row >= 0 && pCur->row < pVtab->pContent->n) {
    switch (col) {
      // path
      case 0:
        sqlite3_result_text(ctx, (pCur->path).c_str(), -1, nullptr);
        break;
      // filename
      case 1:
        sqlite3_result_text(
          ctx,
          (pVtab->pContent->filename[pCur->row]).c_str(),
          -1,
          nullptr
        );
        break;
      // md5
      case 2:
        sqlite3_result_text(
          ctx,
          (pVtab->pContent->md5[pCur->row]).c_str(),
          -1,
          nullptr
        );
        break;
    }
  }
  return SQLITE_OK;
}

/*
** Retrieve the current rowid.
*/
static int hashRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  hash_cursor *pCur = (hash_cursor *)cur;
  // return the value of i, which is set to 0 in xFilter and incremented in
  // xNext
  *pRowid = pCur->row;
  return SQLITE_OK;
}

static int hashEof(sqlite3_vtab_cursor *cur) {
  hash_cursor *pCur = (hash_cursor *)cur;
  hash_vtab *pVtab = (hash_vtab *)cur->pVtab;
  return pCur->row >= pVtab->pContent->n;
}

/*
** Advance the cursor to the next row.
*/
static int hashNext(sqlite3_vtab_cursor *cur) {
  hash_cursor *pCur = (hash_cursor *)cur;
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
static int hashFilter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
) {
  // you need to operate on the sqlite3_vtab_cursor object as your own
  // virtual table's cursor type, so cast it back to x_cursor
  hash_cursor *pCur = (hash_cursor *)pVtabCursor;
  hash_vtab *pVtab = (hash_vtab*)pVtabCursor->pVtab;

  // reset the count value of your cursor's structure
  pCur->row = 0;

  // the hash table requires you to have a where clause to specify the
  // path. if argc is 0, then no values were specified as valid constraints in
  // xBestIndex. there's currently logic in xBestIndex to prevent execution
  // from getting this far if that were to happen, but we check argc here as
  // well to illustrate the requirement
  if (argc <= 0) {
    return SQLITE_MISUSE;
  }

  // extract the RHS value for the path constraint into the cursor's path field
  pCur->path = std::string((const char*)sqlite3_value_text(argv[0]));

  // if the path doesn't exist, return early
  if (!fs::exists(pCur->path)) {
    std::cerr << pCur->path << " doesn't exist" << std::endl;
    return SQLITE_OK;
  }

  // iterate through the directory that is being queried upon and gether the
  // information needed to complete a table scan
  osquery::md5::MD5 md5;
  if (fs::is_regular_file(pCur->path)) {
    pVtab->pContent->filename.push_back(pCur->path);
    const char* filename = pCur->path.c_str();
    const char* md5_value = md5.digestFile(filename);
    pVtab->pContent->md5.push_back(std::string(md5_value));
  } else if (fs::is_directory(pCur->path)) {
    fs::directory_iterator end_iter;
    for (fs::directory_iterator dir_itr(pCur->path);
         dir_itr != end_iter;
         ++dir_itr) {
      pVtab->pContent->filename.push_back(dir_itr->path().string());
      if (fs::is_regular_file(dir_itr->status())) {
        const char* filename = dir_itr->path().string().c_str();
        const char* md5_value = md5.digestFile(filename);
        pVtab->pContent->md5.push_back(std::string(md5_value));
      } else {
        pVtab->pContent->md5.push_back("");
      }
    }
  }

  // set the size of the table based on the amount of results that were queried
  pVtab->pContent->n = pVtab->pContent->filename.size();

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
static int hashBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo) {
  hash_vtab *pVtab = (hash_vtab*)tab;

  if (pIdxInfo->nConstraint == 0) {
    // the hash table requires you to have a where clause to specify the
    // path. if nConstrain is 0, then there were no where clauses.
    goto fail;
  }

  // iterate through all of the constraints (aka where clauses) and look for
  // the constraint on the "path" column
  for (int i = 0; i < pIdxInfo->nConstraint; i++) {
    // if the "path" column is being queried and it's usable
    if (pIdxInfo->aConstraint[i].iColumn == 0 &&
        pIdxInfo->aConstraint[i].usable) {
      // set the argvIndex of the "path" constraint so that it's usable to
      // xBestIndex
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
static sqlite3_module hashModule = {
  0,                           /* iVersion */
  hashCreate,            /* xCreate - create a new virtual table */
  hashCreate,            /* xConnect - connect to an existing vtab */
  hashBestIndex,         /* xBestIndex - find the best query index */
  hashDestroy,           /* xDisconnect - disconnect a vtab */
  hashDestroy,           /* xDestroy - destroy a vtab */
  hashOpen,              /* xOpen - open a cursor */
  hashClose,             /* xClose - close a cursor */
  hashFilter,            /* xFilter - configure scan constraints */
  hashNext,              /* xNext - advance a cursor */
  hashEof,               /* xEof */
  hashColumn,            /* xColumn - read data */
  hashRowid,             /* xRowid - read data */
  0,                           /* xUpdate */
  0,                           /* xBegin */
  0,                           /* xSync */
  0,                           /* xCommit */
  0,                           /* xRollback */
  0,                           /* xFindMethod */
  0,                           /* xRename */
};

/*
** Invoke this routine to create a specific instance of an hash object.
** The new hash object is returned by the 3rd parameter.
**
** Each hash object corresponds to a virtual table in the TEMP table
** with a name of zName.
**
** Destroy the hash object by dropping the virtual table.  If not done
** explicitly by the application, the virtual table will be dropped implicitly
** by the system when the database connection is closed.
*/
int sqlite3_hash_create(
  sqlite3 *db,
  const char *zName,
  sqlite3_hash **ppReturn
) {
  int rc = SQLITE_OK;
  sqlite3_hash *p;

  *ppReturn = p = new sqlite3_hash;

  if(p==0) {
    return SQLITE_NOMEM;
  }
  memset(p, 0, sizeof(*p));

  rc = sqlite3_create_module_v2(db, zName, &hashModule, p,
                                (void(*)(void*))hashFree);
  if(rc==SQLITE_OK) {
    char *zSql;
    zSql = sqlite3_mprintf("CREATE VIRTUAL TABLE temp.%Q USING %Q",
            zName, zName);
    rc = sqlite3_exec(db, zSql, 0, 0, 0);
    sqlite3_free(zSql);
  }

  return rc;
}
