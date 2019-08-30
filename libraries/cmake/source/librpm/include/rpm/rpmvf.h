#ifndef _RPMVF_H
#define _RPMVF_H

/** \ingroup rpmvf
 * \file lib/rpmvf.h
 *
 * \brief Verify a package. The constants that enable/disable some sanity checks (mainly used at post (un)install)
 */
#include <rpm/rpmtypes.h>
#include <rpm/rpmutil.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmvf
 * Bit(s) for rpmVerifyFile() attributes and result.
 */
enum rpmVerifyAttrs_e {
    RPMVERIFY_NONE	= 0,		/*!< */
    RPMVERIFY_MD5	= (1 << 0),	/*!< from %verify(md5) - obsolete */
    RPMVERIFY_FILEDIGEST= (1 << 0),	/*!< from %verify(filedigest) */
    RPMVERIFY_FILESIZE	= (1 << 1),	/*!< from %verify(size) */
    RPMVERIFY_LINKTO	= (1 << 2),	/*!< from %verify(link) */
    RPMVERIFY_USER	= (1 << 3),	/*!< from %verify(user) */
    RPMVERIFY_GROUP	= (1 << 4),	/*!< from %verify(group) */
    RPMVERIFY_MTIME	= (1 << 5),	/*!< from %verify(mtime) */
    RPMVERIFY_MODE	= (1 << 6),	/*!< from %verify(mode) */
    RPMVERIFY_RDEV	= (1 << 7),	/*!< from %verify(rdev) */
    RPMVERIFY_CAPS	= (1 << 8),	/*!< from %verify(caps) */
	/* bits 9-14 unused, reserved for rpmVerifyAttrs */
    RPMVERIFY_CONTEXTS	= (1 << 15),	/*!< verify: from --nocontexts */
	/* bits 16-22 used in rpmVerifyFlags */
	/* bits 23-27 used in rpmQueryFlags */
    RPMVERIFY_READLINKFAIL= (1 << 28),	/*!< readlink failed */
    RPMVERIFY_READFAIL	= (1 << 29),	/*!< file read failed */
    RPMVERIFY_LSTATFAIL	= (1 << 30),	/*!< lstat failed */
    RPMVERIFY_LGETFILECONFAIL	= (1 << 31)	/*!< lgetfilecon failed */
};

typedef rpmFlags rpmVerifyAttrs;

#define	RPMVERIFY_ALL		~(RPMVERIFY_NONE)
#define	RPMVERIFY_FAILURES	\
  (RPMVERIFY_LSTATFAIL|RPMVERIFY_READFAIL|RPMVERIFY_READLINKFAIL|RPMVERIFY_LGETFILECONFAIL)

/** \ingroup rpmvf
 * Bit(s) to control rpmVerify() operation
 */
enum rpmVerifyFlags_e {
    VERIFY_DEFAULT	= 0,		/*!< */
    VERIFY_MD5		= (1 << 0),	/*!< from --nomd5 - obsolete */
    VERIFY_FILEDIGEST	= (1 << 0),	/*!< from --nofiledigest */
    VERIFY_SIZE		= (1 << 1),	/*!< from --nosize */
    VERIFY_LINKTO	= (1 << 2),	/*!< from --nolinkto */
    VERIFY_USER		= (1 << 3),	/*!< from --nouser */
    VERIFY_GROUP	= (1 << 4),	/*!< from --nogroup */
    VERIFY_MTIME	= (1 << 5),	/*!< from --nomtime */
    VERIFY_MODE		= (1 << 6),	/*!< from --nomode */
    VERIFY_RDEV		= (1 << 7),	/*!< from --nodev */
    VERIFY_CAPS		= (1 << 8),	/*!< from --nocaps */
	/* bits 9-14 unused, reserved for rpmVerifyAttrs */
    VERIFY_CONTEXTS	= (1 << 15),	/*!< verify: from --nocontexts */
    VERIFY_FILES	= (1 << 16),	/*!< verify: from --nofiles */
    VERIFY_DEPS		= (1 << 17),	/*!< verify: from --nodeps */
    VERIFY_SCRIPT	= (1 << 18),	/*!< verify: from --noscripts */
    VERIFY_DIGEST	= (1 << 19),	/*!< verify: from --nodigest */
    VERIFY_SIGNATURE	= (1 << 20),	/*!< verify: from --nosignature */
    VERIFY_PATCHES	= (1 << 21),	/*!< verify: from --nopatches */
    VERIFY_HDRCHK	= (1 << 22),	/*!< verify: from --nohdrchk */
    VERIFY_FOR_LIST	= (1 << 23),	/*!< query:  from --list */
    VERIFY_FOR_STATE	= (1 << 24),	/*!< query:  from --state */
    VERIFY_FOR_DOCS	= (1 << 25),	/*!< query:  from --docfiles */
    VERIFY_FOR_CONFIG	= (1 << 26),	/*!< query:  from --configfiles */
    VERIFY_FOR_DUMPFILES= (1 << 27)	/*!< query:  from --dump */
	/* bits 28-31 used in rpmVerifyAttrs */
};

typedef rpmFlags rpmVerifyFlags;

#define	VERIFY_ATTRS	\
  ( VERIFY_FILEDIGEST | VERIFY_SIZE | VERIFY_LINKTO | VERIFY_USER | VERIFY_GROUP | \
    VERIFY_MTIME | VERIFY_MODE | VERIFY_RDEV | VERIFY_CONTEXTS | VERIFY_CAPS )
#define	VERIFY_ALL	\
  ( VERIFY_ATTRS | VERIFY_FILES | VERIFY_DEPS | VERIFY_SCRIPT | VERIFY_DIGEST |\
    VERIFY_SIGNATURE | VERIFY_HDRCHK )

/** \ingroup rpmvf
 * Verify file attributes (including digest).
 * @deprecated		use rpmfiVerify() / rpmfilesVerify() instead
 * @param ts		transaction set
 * @param fi		file info (with linked header and current file index)
 * @retval *res		bit(s) returned to indicate failure
 * @param omitMask	bit(s) to disable verify checks
 * @return		0 on success (or not installed), 1 on error
 */
RPM_GNUC_DEPRECATED
int rpmVerifyFile(const rpmts ts, rpmfi fi,
		rpmVerifyAttrs * res, rpmVerifyAttrs omitMask);


#ifdef __cplusplus
}
#endif

#endif /* _RPMTYPES_H */
