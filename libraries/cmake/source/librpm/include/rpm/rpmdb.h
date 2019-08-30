#ifndef H_RPMDB
#define H_RPMDB

/** \ingroup rpmdb dbi
 * \file lib/rpmdb.h
 * RPM database API.
 */

#include <rpm/rpmtypes.h>
#include <rpm/rpmsw.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Tag value pattern match mode.
 */
typedef enum rpmMireMode_e {
    RPMMIRE_DEFAULT	= 0,	/*!< regex with \., .* and ^...$ added */
    RPMMIRE_STRCMP	= 1,	/*!< strings  using strcmp(3) */
    RPMMIRE_REGEX	= 2,	/*!< regex(7) patterns through regcomp(3) */
    RPMMIRE_GLOB	= 3	/*!< glob(7) patterns through fnmatch(3) */
} rpmMireMode;

typedef enum rpmdbOpX_e {
    RPMDB_OP_DBGET              = 1,
    RPMDB_OP_DBPUT              = 2,
    RPMDB_OP_DBDEL              = 3,
    RPMDB_OP_MAX		= 4
} rpmdbOpX;

typedef enum rpmdbCtrlOp_e {
    RPMDB_CTRL_LOCK_RO         = 1,
    RPMDB_CTRL_UNLOCK_RO       = 2,
    RPMDB_CTRL_LOCK_RW         = 3,
    RPMDB_CTRL_UNLOCK_RW       = 4,
    RPMDB_CTRL_INDEXSYNC       = 5
} rpmdbCtrlOp;

/** \ingroup rpmdb
 * Retrieve operation timestamp from rpm database.
 * @param db            rpm database
 * @param opx           operation timestamp index
 * @return              pointer to operation timestamp.
 */
rpmop rpmdbOp(rpmdb db, rpmdbOpX opx);

/** \ingroup rpmdb
 * Open all database indices.
 * @param db		rpm database
 * @return		0 on success
 */
int rpmdbOpenAll (rpmdb db);

/** \ingroup rpmdb
 * Return number of instances of package in rpm database.
 * @param db		rpm database
 * @param name		rpm package name
 * @return		number of instances
 */
int rpmdbCountPackages(rpmdb db, const char * name);

/** \ingroup rpmdb
 * Return header join key for current position of rpm database iterator.
 * @param mi		rpm database iterator
 * @return		current header join key
 */
unsigned int rpmdbGetIteratorOffset(rpmdbMatchIterator mi);

/** \ingroup rpmdb
 * Return number of elements in rpm database iterator.
 * @param mi		rpm database iterator
 * @return		number of elements
 */
int rpmdbGetIteratorCount(rpmdbMatchIterator mi);

/** \ingroup rpmdb
 */
unsigned int rpmdbGetIteratorFileNum(rpmdbMatchIterator mi);

/** \ingroup rpmdb
 * Append items to set of package instances to iterate.
 * @param mi		rpm database iterator
 * @param hdrNums	array of package instances
 * @param nHdrNums	number of elements in array
 * @return		0 on success, 1 on failure (bad args)
 */
int rpmdbAppendIterator(rpmdbMatchIterator mi,
			const unsigned int * hdrNums, unsigned int nHdrNums);

/** \ingroup rpmdb
 * Add pattern to iterator selector.
 * @param mi		rpm database iterator
 * @param tag		rpm tag
 * @param mode		type of pattern match
 * @param pattern	pattern to match
 * @return		0 on success
 */
int rpmdbSetIteratorRE(rpmdbMatchIterator mi, rpmTagVal tag,
		rpmMireMode mode, const char * pattern);

/** \ingroup rpmdb
 * Prepare iterator for lazy writes.
 * @note Must be called before rpmdbNextIterator() with CDB model database.
 * @param mi		rpm database iterator
 * @param rewrite	new value of rewrite
 * @return		previous value
 */
int rpmdbSetIteratorRewrite(rpmdbMatchIterator mi, int rewrite);

/** \ingroup rpmdb
 * Modify iterator to mark header for lazy write on release.
 * @param mi		rpm database iterator
 * @param modified	new value of modified
 * @return		previous value
 */
int rpmdbSetIteratorModified(rpmdbMatchIterator mi, int modified);

/** \ingroup rpmdb
 * Modify iterator to verify retrieved header blobs.
 * @param mi		rpm database iterator
 * @param ts		transaction set
 * @param (*hdrchk)	headerCheck() vector
 * @return		0 always
 */
int rpmdbSetHdrChk(rpmdbMatchIterator mi, rpmts ts,
	rpmRC (*hdrchk) (rpmts ts, const void * uh, size_t uc, char ** msg));

/** \ingroup rpmdb
 * Return database iterator.
 * @param db		rpm database
 * @param rpmtag	database index tag
 * @param keyp		key data (NULL for sequential access)
 * @param keylen	key data length (0 will use strlen(keyp))
 * @return		NULL on failure
 */
rpmdbMatchIterator rpmdbInitIterator(rpmdb db, rpmDbiTagVal rpmtag,
			const void * keyp, size_t keylen);

/** \ingroup rpmdb
 * Return next package header from iteration.
 * @param mi		rpm database iterator
 * @return		NULL on end of iteration.
 */
Header rpmdbNextIterator(rpmdbMatchIterator mi);

/** \ingroup rpmdb
 * Destroy rpm database iterator.
 * @param mi		rpm database iterator
 * @return		NULL always
 */
rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi);

/** \ingroup rpmdb
 * Get an iterator for an index
 * @param db		rpm database
 * @param rpmtag	the index to iterate over
 * @return		the index iterator
 */
rpmdbIndexIterator rpmdbIndexIteratorInit(rpmdb db, rpmDbiTag rpmtag);

/** \ingroup rpmdb
 * Get the next key - Warning! Keys are not zero terminated!
 * Binary tags may even contain zero bytes
 * @param ii		index iterator
 * @param key		address to save the pointer to the key
 * @param keylen	address to save the length of the key to
 * @return 		0 on success; != 0 on error or end of index
 */
int rpmdbIndexIteratorNext(rpmdbIndexIterator ii, const void ** key, size_t * keylen);

/** \ingroup rpmdb
 * Get the next key into a tag data container.
 * Caller is responsible for calling rpmtdFreeData() to freeing the
 * data returned in keytd once done with it.
 * @param ii		index iterator
 * @param keytd		tag container to store the key in
 * @return 		0 on success; != 0 on error or end of index
 */
int rpmdbIndexIteratorNextTd(rpmdbIndexIterator ii, rpmtd keytd);

/** \ingroup rpmdb
 * Get number of entries for current key
 * @param ii            index iterator
 * @return		number of entries. 0 on error.
 */
unsigned int rpmdbIndexIteratorNumPkgs(rpmdbIndexIterator ii);

/** \ingroup rpmdb
 * Get package offset of entry
 * @param ii            index iterator
 * @param nr		number of the entry
 * @return		db offset of pkg
 */
unsigned int rpmdbIndexIteratorPkgOffset(rpmdbIndexIterator ii, unsigned int nr);

/** \ingroup rpmdb
 * Get tag number of entry
 * @param ii            index iterator
 * @param nr		number of the entry
 * @return		number of tag within the package
 */
unsigned int rpmdbIndexIteratorTagNum(rpmdbIndexIterator ii, unsigned int nr);

/** \ingroup rpmdb
 * Free index iterator
 * @param ii            index iterator
 * return 		NULL
 */
rpmdbIndexIterator rpmdbIndexIteratorFree(rpmdbIndexIterator ii);

/** \ingroup rpmdb
 * manipulate the rpm database
 * @param db		rpm database
 * @param ctrl		operation
 * @return 		0 on success; != 0 on error
 */
int rpmdbCtrl(rpmdb db, rpmdbCtrlOp ctrl);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMDB */
