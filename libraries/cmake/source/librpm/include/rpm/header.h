#ifndef H_HEADER
#define H_HEADER

/** \ingroup header
 * \file lib/header.h
 *
 * An rpm header carries all information about a package. A header is
 * a collection of data elements called tags. Each tag has a data type,
 * and includes 1 or more values.
 * 
 */

/* RPM - Copyright (C) 1995-2001 Red Hat Software */

#include <rpm/rpmio.h>
#include <rpm/rpmtypes.h>
#include <rpm/rpmtd.h>
#include <rpm/rpmutil.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup header 
 * Header magic value
 */ 
extern const unsigned char rpm_header_magic[8];

/** \ingroup header
 * Include calculation for 8 bytes of (magic, 0)?
 */
enum hMagic {
    HEADER_MAGIC_NO		= 0,
    HEADER_MAGIC_YES		= 1
};

/** \ingroup header
 * Create new (empty) header instance.
 * @return		header
 */
Header headerNew(void);

/** \ingroup header
 * Dereference a header instance.
 * @param h		header
 * @return		NULL always
 */
Header headerFree( Header h);

/** \ingroup header
 * Reference a header instance.
 * @param h		header
 * @return		new header reference
 */
Header headerLink(Header h);

/** \ingroup header
 * Return size of on-disk header representation in bytes.
 * @param h		header
 * @param magicp	include size of 8 bytes for (magic, 0)?
 * @return		size of on-disk header
 */
unsigned int headerSizeof(Header h, int magicp);

/** \ingroup header
 * Convert header to on-disk representation.
 * @deprecated		Use headerExport() instead
 * @param h		header (with pointers)
 * @return		on-disk header blob (i.e. with offsets)
 */
void * headerUnload(Header h);

/** \ingroup header
 * Export header to on-disk representation.
 * @param h		header (with pointers)
 * @retval bsize	on-disk header blob size in bytes
 * @return		on-disk header blob (i.e. with offsets)
 */
void * headerExport(Header h, unsigned int * bsize);

/** \ingroup header
 * Convert header to on-disk representation, and then reload.
 * This is used to insure that all header data is in one chunk.
 * @param h		header (with pointers)
 * @param tag		region tag
 * @return		on-disk header (with offsets)
 */
Header headerReload(Header h, rpmTagVal tag);

/** \ingroup header
 * Duplicate a header.
 * @param h		header
 * @return		new header instance
 */
Header headerCopy(Header h);

/** \ingroup header
 * Convert header to in-memory representation.
 * @deprecated		Use headerImport() instead
 * @param uh		on-disk header blob (i.e. with offsets)
 * @return		header
 */
Header headerLoad(void * uh);

/** \ingroup header
 * Make a copy and convert header to in-memory representation.
 * @deprecated		Use headerImport() instead
 * @param uh		on-disk header blob (i.e. with offsets)
 * @return		header
 */
Header headerCopyLoad(const void * uh);

enum headerImportFlags_e {
    HEADERIMPORT_COPY		= (1 << 0), /* Make copy of blob on import? */
    HEADERIMPORT_FAST		= (1 << 1), /* Faster but less safe? */
};

typedef rpmFlags headerImportFlags;

/** \ingroup header
 * Import header to in-memory representation.
 * @param blob		on-disk header blob (i.e. with offsets)
 * @param bsize		on-disk header blob size in bytes (0 if unknown)
 * @param flags		flags to control operation
 * @return		header
 */
Header headerImport(void *blob, unsigned int bsize, headerImportFlags flags);

/** \ingroup header
 * Read (and load) header from file handle.
 * @param fd		file handle
 * @param magicp	read (and verify) 8 bytes of (magic, 0)?
 * @return		header (or NULL on error)
 */
Header headerRead(FD_t fd, int magicp);

/** \ingroup header
 * Write (with unload) header to file handle.
 * @param fd		file handle
 * @param h		header
 * @param magicp	prefix write with 8 bytes of (magic, 0)?
 * @return		0 on success, 1 on error
 */
int headerWrite(FD_t fd, Header h, int magicp);

/** \ingroup header
 * Check if tag is in header.
 * @param h		header
 * @param tag		tag
 * @return		1 on success, 0 on failure
 */
int headerIsEntry(Header h, rpmTagVal tag);

/** \ingroup header
 * Modifier flags for headerGet() operation.
 * For consistent behavior you'll probably want to use ALLOC to ensure
 * the caller owns the data, but MINMEM is useful for avoiding extra
 * copy of data when you are sure the header wont go away.
 * Most of the time you'll probably want EXT too, but note that extensions 
 * tags don't generally honor the other flags, MINMEM, RAW, ALLOC and ARGV 
 * are only relevant for non-extension data.
 */
enum headerGetFlags_e {
    HEADERGET_DEFAULT	= 0,	    /* legacy headerGetEntry() behavior */
    HEADERGET_MINMEM 	= (1 << 0), /* pointers can refer to header memory */
    HEADERGET_EXT 	= (1 << 1), /* lookup extension types too */
    HEADERGET_RAW 	= (1 << 2), /* return raw contents (no i18n lookups) */
    HEADERGET_ALLOC	= (1 << 3), /* always allocate memory for all data */
    HEADERGET_ARGV	= (1 << 4), /* return string arrays NULL-terminated */
};

typedef rpmFlags headerGetFlags;

/** \ingroup header
 * Retrieve tag value.
 * @param h		header
 * @param tag		tag
 * @retval td		tag data container
 * @param flags		retrieval modifier flags
 * @return		1 on success, 0 on failure
 */
int headerGet(Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags);


enum headerPutFlags_e {
    HEADERPUT_DEFAULT	= 0,
    HEADERPUT_APPEND 	= (1 << 0),
};

typedef rpmFlags headerPutFlags;

/** \ingroup header
 * Add or append tag to header.
 *
 * @param h		header
 * @param td		tag data container
 * @param flags		flags to control operation
 * @return		1 on success, 0 on failure
 */
int headerPut(Header h, rpmtd td, headerPutFlags flags);

/** \ingroup header 
 * @{
 * Type-safe methods for inserting tag data to header.
 * Tag data type is validated to match the function type, ie things like
 * headerPutUint32(h, RPMTAG_NAME, ...) will return failure. For non-array
 * types size must equal 1, and data is checked to be non-NULL. For array
 * types, add-or-append mode is always used.
 *
 * headerPutString() can be used on both RPM_STRING_TYPE and 
 * RPM_STRING_ARRAY_TYPE (to add a single string into the array) tags,
 * for others the type must match exactly.
 *
 * These are intended to "do the right thing" in the common case, if you 
 * need more fine grained control use headerPut() & friends instead.
 * @todo		Make doxygen group these meaningfully.
 *
 * @param h		header
 * @param tag		tag to insert
 * @param val		pointer to value(s)
 * @param size		number of items in array (1 or larger)
 * @return		1 on success, 0 on failure
 * 
 */
int headerPutBin(Header h, rpmTagVal tag, const uint8_t *val, rpm_count_t size);
int headerPutString(Header h, rpmTagVal tag, const char *val);
int headerPutStringArray(Header h, rpmTagVal tag, const char **val, rpm_count_t size);
int headerPutChar(Header h, rpmTagVal tag, const char *val, rpm_count_t size);
int headerPutUint8(Header h, rpmTagVal tag, const uint8_t *val, rpm_count_t size);
int headerPutUint16(Header h, rpmTagVal tag, const uint16_t *val, rpm_count_t size);
int headerPutUint32(Header h, rpmTagVal tag, const uint32_t *val, rpm_count_t size);
int headerPutUint64(Header h, rpmTagVal tag, const uint64_t *val, rpm_count_t size);
/** @} */

/** \ingroup header
 * Add locale specific tag to header.
 * A NULL lang is interpreted as the C locale. Here are the rules:
 * \verbatim
 *	- If the tag isn't in the header, it's added with the passed string
 *	   as new value.
 *	- If the tag occurs multiple times in entry, which tag is affected
 *	   by the operation is undefined.
 *	- If the tag is in the header w/ this language, the entry is
 *	   *replaced* (like headerMod()).
 * \endverbatim
 * This function is intended to just "do the right thing". If you need
 * more fine grained control use headerPut() and headerMod().
 *
 * @param h		header
 * @param tag		tag
 * @param string	tag value
 * @param lang		locale
 * @return		1 on success, 0 on failure
 */
int headerAddI18NString(Header h, rpmTagVal tag, const char * string,
		const char * lang);

/** \ingroup header
 * Modify tag in header.
 * If there are multiple entries with this tag, the first one gets replaced.
 * @param h		header
 * @param td		tag data container
 * @return		1 on success, 0 on failure
 */
int headerMod(Header h, rpmtd td);

/** \ingroup header
 * Delete tag in header.
 * Removes all entries of type tag from the header, returns 1 if none were
 * found.
 *
 * @param h		header
 * @param tag		tag
 * @return		0 on success, 1 on failure (INCONSISTENT)
 */
int headerDel(Header h, rpmTagVal tag);

/** \ingroup header
 * Return formatted output string from header tags.
 * The returned string must be free()d.
 *
 * @param h		header
 * @param fmt		format to use
 * @retval errmsg	error message (if any)
 * @return		formatted output string (malloc'ed)
 */
char * headerFormat(Header h, const char * fmt, errmsg_t * errmsg);

/** \ingroup header
 * Duplicate tag values from one header into another.
 * @param headerFrom	source header
 * @param headerTo	destination header
 * @param tagstocopy	array of tags that are copied
 */
void headerCopyTags(Header headerFrom, Header headerTo, 
		    const rpmTagVal * tagstocopy);

/** \ingroup header
 * Destroy header tag iterator.
 * @param hi		header tag iterator
 * @return		NULL always
 */
HeaderIterator headerFreeIterator(HeaderIterator hi);

/** \ingroup header
 * Create header tag iterator.
 * @param h		header
 * @return		header tag iterator
 */
HeaderIterator headerInitIterator(Header h);

/** \ingroup header
 * Return next tag contents from header.
 * @param hi		header tag iterator
 * @retval td		tag data container
 * @return		1 on success, 0 on failure
 */
int headerNext(HeaderIterator hi, rpmtd td);

/** \ingroup header
 * Return next tag number from header.
 * @param hi		header tag iterator
 * @return		next tag, RPMTAG_NOT_FOUND to stop iteration
 */
rpmTagVal headerNextTag(HeaderIterator hi);

/** \ingroup header
 * Return any non-array tag from header, converted to string
 * @param h		header
 * @param tag		tag to retrieve
 * @return 		string pointer (malloced) or NULL on failure
 */
char * headerGetAsString(Header h, rpmTagVal tag);

/** \ingroup header
 * Return a simple string tag from header
 * @param h		header
 * @param tag		tag to retrieve
 * @return		string pointer (to header memory) or NULL on failure
 */
const char * headerGetString(Header h, rpmTagVal tag);

/* \ingroup header
 * Return a simple number tag (or extension) from header
 * @param h		header
 * @param tag		tag to retrieve
 * @return		numeric tag value or 0 on failure
 */
uint64_t headerGetNumber(Header h, rpmTagVal tag);

/** \ingroup header
 * Check if header is a source or binary package header
 * @param h		header
 * @return		0 == binary, 1 == source
 */
int headerIsSource(Header h);

/** \ingroup header
 * Return header instance, ie is the header from rpmdb.
 * @param h		header
 * @return		rpmdb record number or 0
 */
unsigned int headerGetInstance(Header h);

typedef enum headerConvOps_e {
    HEADERCONV_EXPANDFILELIST	= 0,
    HEADERCONV_COMPRESSFILELIST = 1,
    HEADERCONV_RETROFIT_V3	= 2,
} headerConvOps;

/** \ingroup header
 * Convert header to/from (legacy) data presentation
 * @param h		header
 * @param op		one of headerConvOps operations
 * @return		1 on success, 0 on failure
 */
int headerConvert(Header h, int op);

#ifdef __cplusplus
}
#endif

#endif	/* H_HEADER */
