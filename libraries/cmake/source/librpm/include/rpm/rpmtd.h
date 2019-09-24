#ifndef _RPMTD_H
#define _RPMTD_H

/** \ingroup rpmtd
 *  \file lib/rpmtd.h
 *
 *  RPM Tag Data Container API
 */

#include <rpm/rpmtypes.h>
#include <rpm/argv.h>

#ifdef __cplusplus
extern "C" {
#endif

enum rpmtdFlags_e {
    RPMTD_NONE		= 0,
    RPMTD_ALLOCED	= (1 << 0),	/* was memory allocated? */
    RPMTD_PTR_ALLOCED	= (1 << 1),	/* were array pointers allocated? */
    RPMTD_IMMUTABLE	= (1 << 2),	/* header data or modifiable? */
    RPMTD_ARGV		= (1 << 3),	/* string array is NULL-terminated? */
    RPMTD_INVALID	= (1 << 4),	/* invalid data (in header) */
};

typedef rpmFlags rpmtdFlags;

/** \ingroup rpmtd
 * Container for rpm tag data (from headers or extensions).
 * @todo		Make this opaque (at least outside rpm itself)
 */
struct rpmtd_s {
    rpm_tag_t tag;	/* rpm tag of this data entry*/
    rpm_tagtype_t type;	/* data type */
    rpm_count_t count;	/* number of entries */
    rpm_data_t data;	/* pointer to actual data */
    rpmtdFlags flags;	/* flags on memory allocation etc */
    int ix;		/* iteration index */
    rpm_count_t size;	/* size of data (only works for RPMTD_IMMUTABLE atm) */
};

/** \ingroup rpmtd
 * Create new tag data container
 * @return		New, initialized tag data container.
 */
rpmtd rpmtdNew(void);

/** \ingroup rpmtd
 * Destroy tag data container.
 * @param td		Tag data container
 * @return		NULL always
 */
rpmtd rpmtdFree(rpmtd td);
 
/** \ingroup rpmtd
 * (Re-)initialize tag data container. Contents will be zeroed out
 * and iteration index reset.
 * @param td		Tag data container
 */
void rpmtdReset(rpmtd td);

/** \ingroup rpmtd
 * Free contained data. This is always safe to call as the container knows 
 * if data was malloc'ed or not. Container is reinitialized.
 * @param td		Tag data container
 */
void rpmtdFreeData(rpmtd td);

/** \ingroup rpmtd
 * Retrieve array size of the container. For non-array types this is always 1.
 * @param td		Tag data container
 * @return		Number of entries in contained data.
 */
rpm_count_t rpmtdCount(rpmtd td);

/** \ingroup rpmtd
 * Retrieve container data size (eg required for allocation).
 * Note this currently only works for RPMTD_IMMUTABLE data.
 * @param td		Tag data container
 * @return		Data size in bytes.
 */
rpm_count_t rpmtdSize(rpmtd td);

/** \ingroup rpmtd
 * Retrieve tag of the container.
 * @param td		Tag data container
 * @return		Rpm tag.
 */
rpmTagVal rpmtdTag(rpmtd td);

/** \ingroup rpmtd
 * Retrieve type of the container.
 * @param td		Tag data container
 * @return		Rpm tag type.
 */
rpmTagType rpmtdType(rpmtd td);

/** \ingroup rpmtd
 * Retrieve class of the container.
 * @param td		Tag data container
 * @return		Rpm tag class
 */
rpmTagClass rpmtdClass(rpmtd td);

/** \ingroup rpmtd
 * Retrieve flags of the container (allocation details etc)
 * @param td		Tag data container
 * @return		Container flags
 */
rpmtdFlags rpmtdGetFlags(rpmtd td);

/** \ingroup rpmtd
 * Retrieve current iteration index of the container.
 * @param td		Tag data container
 * @return		Iteration index (or -1 if not iterating)
 */
int rpmtdGetIndex(rpmtd td);

/** \ingroup rpmtd
 * Set iteration index of the container.
 * If new index is out of bounds for the container, -1 is returned and
 * iteration index is left untouched. 
 * @param td		Tag data container
 * @param index		New index
 * @return		New index, or -1 if index out of bounds
 */
int rpmtdSetIndex(rpmtd td, int index);

/** \ingroup rpmtd
 * Initialize tag container for iteration
 * @param td		Tag data container
 * @return		0 on success
 */
int rpmtdInit(rpmtd td);

/** \ingroup rpmtd
 * Iterate over tag data container.
 * @param td		Tag data container
 * @return		Tag data container iterator index, -1 on termination
 */
int rpmtdNext(rpmtd td);

/** \ingroup rpmtd
 * Iterate over uint32_t type tag data container.
 * @param td		Tag data container
 * @return		Pointer to next value, NULL on termination or error
 */
uint32_t *rpmtdNextUint32(rpmtd td);

/** \ingroup rpmtd
 * Iterate over uint64_t type tag data container.
 * @param td		Tag data container
 * @return		Pointer to next value, NULL on termination or error
 */
uint64_t *rpmtdNextUint64(rpmtd td);

/** \ingroup rpmtd
 * Iterate over string / string array type tag data container.
 * @param td		Tag data container
 * @return		Pointer to next value, NULL on termination or error
 */
const char *rpmtdNextString(rpmtd td);

/** \ingroup rpmtd
 * Return char data from tag container.
 * For scalar return type, just return pointer to the integer. On array
 * types, return pointer to current iteration index. If the tag container
 * is not for char type, NULL is returned.
 * @param td		Tag data container
 * @return		Pointer to uint16_t, NULL on error
 */
char *rpmtdGetChar(rpmtd td);

/** \ingroup rpmtd
 * Return uint16_t data from tag container.
 * For scalar return type, just return pointer to the integer. On array
 * types, return pointer to current iteration index. If the tag container
 * is not for int16 type, NULL is returned.
 * @param td		Tag data container
 * @return		Pointer to uint16_t, NULL on error
 */
uint16_t * rpmtdGetUint16(rpmtd td);

/** \ingroup rpmtd
 * Return uint32_t data from tag container.
 * For scalar return type, just return pointer to the integer. On array
 * types, return pointer to current iteration index. If the tag container
 * is not for int32 type, NULL is returned.
 * @param td		Tag data container
 * @return		Pointer to uint32_t, NULL on error
 */
uint32_t * rpmtdGetUint32(rpmtd td);

/** \ingroup rpmtd
 * Return uint64_t data from tag container.
 * For scalar return type, just return pointer to the integer. On array
 * types, return pointer to current iteration index. If the tag container
 * is not for int64 type, NULL is returned.
 * @param td		Tag data container
 * @return		Pointer to uint64_t, NULL on error
 */
uint64_t * rpmtdGetUint64(rpmtd td);

/** \ingroup rpmtd
 * Return string data from tag container.
 * For string types, just return the string. On string array types,
 * return the string from current iteration index. If the tag container
 * is not for a string type, NULL is returned.
 * @param td		Tag data container
 * @return		String constant from container, NULL on error
 */
const char * rpmtdGetString(rpmtd td);

/** \ingroup rpmtd
 * Return numeric value from tag container.
 * Returns the value of numeric container (RPM_NUMERIC_CLASS) from
 * current iteration index as uint64_t regardless of its internal 
 * presentation (8/16/32/64-bit integer).
 * @param td		Tag data container
 * @return		Value of current iteration item as uint64_t,
 * 			0 for non-numeric types (error)
 */
uint64_t rpmtdGetNumber(rpmtd td);

typedef enum rpmtdFormats_e {
    RPMTD_FORMAT_STRING		= 0,	/* plain string (any type) */
    RPMTD_FORMAT_ARMOR		= 1,	/* ascii armor format (bin types) */
    RPMTD_FORMAT_BASE64		= 2,	/* base64 encoding (bin types) */
    RPMTD_FORMAT_PGPSIG		= 3,	/* pgp/gpg signature (bin types) */
    RPMTD_FORMAT_DEPFLAGS	= 4,	/* dependency flags (int types) */
    RPMTD_FORMAT_FFLAGS		= 5,	/* file flags (int types) */
    RPMTD_FORMAT_PERMS		= 6,	/* permission string (int types) */
    RPMTD_FORMAT_TRIGGERTYPE	= 7,	/* trigger types (int types) */
    RPMTD_FORMAT_XML		= 8,	/* xml format (any type) */
    RPMTD_FORMAT_OCTAL		= 9,	/* octal format (int types) */
    RPMTD_FORMAT_HEX		= 10,	/* hex format (int types) */
    RPMTD_FORMAT_DATE		= 11,	/* date format (int types) */
    RPMTD_FORMAT_DAY		= 12,	/* day format (int types) */
    RPMTD_FORMAT_SHESCAPE	= 13,	/* shell escaped (any type) */
    RPMTD_FORMAT_ARRAYSIZE	= 14,	/* size of contained array (any type) */
    RPMTD_FORMAT_DEPTYPE	= 15,	/* dependency types (int types) */
    RPMTD_FORMAT_FSTATE		= 16,	/* file states (int types) */
    RPMTD_FORMAT_VFLAGS		= 17,	/* file verify flags (int types) */
    RPMTD_FORMAT_EXPAND		= 18,	/* macro expansion (string types) */
    RPMTD_FORMAT_FSTATUS	= 19,	/* file verify status (int types) */
} rpmtdFormats;

/** \ingroup rpmtd
 * Format data from tag container to string presentation of given format.
 * Return malloced string presentation of current data in container,
 * converting from integers etc as necessary. On array types, data from
 * current iteration index is used for formatting.
 * @param td		Tag data container
 * @param fmt		Format to apply
 * @param errmsg	Error message from conversion (or NULL)
 * @return		String representation of current data (malloc'ed), 
 * 			NULL on error
 */
char *rpmtdFormat(rpmtd td, rpmtdFormats fmt, const char *errmsg);

/** \ingroup rpmtd
 * Set container tag and type.
 * For empty container, any valid tag can be set. If the container has
 * data, changing is only permitted to tag of same type. 
 * @param td		Tag data container
 * @param tag		New tag
 * @return		1 on success, 0 on error
 */
int rpmtdSetTag(rpmtd td, rpmTagVal tag);

/** \ingroup rpmtd
 * Construct tag container from uint8_t pointer.
 * Tag type is checked to be of compatible type (CHAR, INT8 or BIN). 
 * For non-array types (BIN is a special case of INT8 array) 
 * count must be exactly 1.
 * @param td		Tag data container
 * @param tag		Rpm tag to construct
 * @param data		Pointer to uint8_t (value or array)
 * @param count		Number of entries
 * @return		1 on success, 0 on error (eg wrong type)
 */
int rpmtdFromUint8(rpmtd td, rpmTagVal tag, uint8_t *data, rpm_count_t count);

/** \ingroup rpmtd
 * Construct tag container from uint16_t pointer.
 * Tag type is checked to be of INT16 type. For non-array types count
 * must be exactly 1.
 * @param td		Tag data container
 * @param tag		Rpm tag to construct
 * @param data		Pointer to uint16_t (value or array)
 * @param count		Number of entries
 * @return		1 on success, 0 on error (eg wrong type)
 */
int rpmtdFromUint16(rpmtd td, rpmTagVal tag, uint16_t *data, rpm_count_t count);

/** \ingroup rpmtd
 * Construct tag container from uint32_t pointer.
 * Tag type is checked to be of INT32 type. For non-array types count
 * must be exactly 1.
 * @param td		Tag data container
 * @param tag		Rpm tag to construct
 * @param data		Pointer to uint32_t (value or array)
 * @param count		Number of entries
 * @return		1 on success, 0 on error (eg wrong type)
 */
int rpmtdFromUint32(rpmtd td, rpmTagVal tag, uint32_t *data, rpm_count_t count);

/** \ingroup rpmtd
 * Construct tag container from uint64_t pointer.
 * Tag type is checked to be of INT64 type. For non-array types count
 * must be exactly 1.
 * @param td		Tag data container
 * @param tag		Rpm tag to construct
 * @param data		Pointer to uint64_t (value or array)
 * @param count		Number of entries
 * @return		1 on success, 0 on error (eg wrong type)
 */
int rpmtdFromUint64(rpmtd td, rpmTagVal tag, uint64_t *data, rpm_count_t count);

/** \ingroup rpmtd
 * Construct tag container from a string.
 * Tag type is checked to be of string type. 
 * @param td		Tag data container
 * @param tag		Rpm tag to construct
 * @param data		String to use
 * @return		1 on success, 0 on error (eg wrong type)
 */
int rpmtdFromString(rpmtd td, rpmTagVal tag, const char *data);

/** \ingroup rpmtd
 * Construct tag container from a string array.
 * Tag type is checked to be of string or string array type. For non-array
 * types count must be exactly 1.
 * @param td		Tag data container
 * @param tag		Rpm tag to construct
 * @param data		Pointer to string array
 * @param count		Number of entries
 * @return		1 on success, 0 on error (eg wrong type)
 */
int rpmtdFromStringArray(rpmtd td, rpmTagVal tag, const char **data, rpm_count_t count);

/** \ingroup rpmtd
 * Construct tag container from ARGV_t array.
 * Tag type is checked to be of string array type and array is checked
 * to be non-empty.
 * @param td		Tag data container
 * @param tag		Rpm tag to construct
 * @param argv		ARGV array
 * @return		1 on success, 0 on error (eg wrong type)
 */
int rpmtdFromArgv(rpmtd td, rpmTagVal tag, ARGV_t argv);

/** \ingroup rpmtd
 * Construct tag container from ARGI_t array.
 * Tag type is checked to be of integer array type and array is checked
 * to be non-empty.
 * @param td		Tag data container
 * @param tag		Rpm tag to construct
 * @param argi		ARGI array
 * @return		1 on success, 0 on error (eg wrong type)
 */
int rpmtdFromArgi(rpmtd td, rpmTagVal tag, ARGI_t argi);

/* \ingroup rpmtd
 * Perform deep copy of container.
 * Create a modifiable copy of tag data container (on string arrays each
 * string is separately allocated)
 * @todo		Only string arrays types are supported currently
 * @param td		Container to copy
 * @return		New container or NULL on error
 */
rpmtd rpmtdDup(rpmtd td);

/* \ingroup rpmtd
 * Push string array container contents to a string pool, return string ids.
 * @param td		Tag data container
 * @param pool		String pool
 * @return		Array of string id's (malloced)
 */
rpmsid * rpmtdToPool(rpmtd td, rpmstrPool pool);

#ifdef __cplusplus
}
#endif

#endif /* _RPMTD_H */
