#ifndef _RPMTYPES_H
#define _RPMTYPES_H

/** \ingroup rpmtypes
 * \file lib/rpmtypes.h
 *
 * Typedefs for RPM abstract data types.
 * @todo The grouping needs love to look sane...
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef const char *    errmsg_t;

/** \ingroup rpmtypes
 *
 * RPM header and data retrieval types.
 * @{
 */
typedef struct headerToken_s * Header;
typedef struct headerIterator_s * HeaderIterator;

typedef int32_t		rpm_tag_t;
typedef uint32_t	rpm_tagtype_t;
typedef uint32_t	rpm_count_t;
typedef rpm_tag_t	rpmTagVal;
typedef rpm_tag_t	rpmDbiTagVal;

typedef void *		rpm_data_t;
typedef const void *	rpm_constdata_t;

typedef struct rpmtd_s * rpmtd;

typedef uint32_t	rpm_color_t;
typedef uint32_t	rpm_flag_t;
typedef uint32_t	rpm_tid_t;

typedef uint32_t	rpmFlags;
/** @} */

/** \ingroup rpmtypes
 *
 * In-header hardcoded sizes for various POSIXy types
 * @{
 */
typedef uint32_t	rpm_off_t;
typedef uint64_t	rpm_loff_t;
typedef uint32_t	rpm_time_t;
typedef uint16_t	rpm_mode_t;
typedef uint16_t	rpm_rdev_t;
typedef uint32_t	rpm_dev_t;
typedef uint32_t	rpm_ino_t;
/** @} */

/** \ingroup rpmtypes
 * The main types involved in transaction manipulation 
 * @{
 */
typedef struct rpmts_s * rpmts;
typedef struct rpmte_s * rpmte;
typedef struct rpmds_s * rpmds;
typedef struct rpmfi_s * rpmfi;
typedef struct rpmfiles_s * rpmfiles;
typedef struct rpmdb_s * rpmdb;
typedef struct rpmdbMatchIterator_s * rpmdbMatchIterator;
typedef struct rpmtsi_s * rpmtsi;
typedef struct rpmps_s * rpmps;
typedef struct rpmtxn_s * rpmtxn;

typedef struct rpmdbIndexIterator_s * rpmdbIndexIterator;
typedef const void * fnpyKey;
typedef void * rpmCallbackData;
/** @} */

typedef struct rpmPubkey_s * rpmPubkey;
typedef struct rpmKeyring_s * rpmKeyring;

typedef uint32_t rpmsid;
typedef struct rpmstrPool_s * rpmstrPool;

typedef struct rpmPlugin_s * rpmPlugin;
typedef struct rpmPlugins_s * rpmPlugins;

typedef struct rpmgi_s * rpmgi;

typedef struct rpmSpec_s * rpmSpec;

typedef struct rpmRelocation_s rpmRelocation;


/** \ingroup rpmtypes 
 * RPM IO file descriptor type
 */
typedef struct _FD_s * FD_t;

/** \ingroup rpmtypes
 * Package read return codes.
 */
typedef	enum rpmRC_e {
    RPMRC_OK		= 0,	/*!< Generic success code */
    RPMRC_NOTFOUND	= 1,	/*!< Generic not found code. */
    RPMRC_FAIL		= 2,	/*!< Generic failure code. */
    RPMRC_NOTTRUSTED	= 3,	/*!< Signature is OK, but key is not trusted. */
    RPMRC_NOKEY		= 4	/*!< Public key is unavailable. */
} rpmRC;

#ifdef __cplusplus
}
#endif

/* XXX included late as rpmtag.h depends on our definitions here... */
#include <rpm/rpmtag.h>

#endif /* _RPMTYPES_H */
