#ifndef _RPMFILES_H
#define _RPMFILES_H

/** \ingroup rpmfilesles
 * \file lib/rpmfiles.h
 * File info set API.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rpm/rpmtypes.h>
#include <rpm/rpmvf.h>
#include <rpm/rpmpgp.h>

/** \ingroup rpmfiles
 * File types.
 * These are the file types used internally by rpm. The file
 * type is determined by applying stat(2) macros like S_ISDIR to
 * the file mode tag from a header. The values are arbitrary,
 * but are identical to the linux stat(2) file types.
 */
typedef enum rpmFileTypes_e {
    PIPE	=  1,	/*!< pipe/fifo */
    CDEV	=  2,	/*!< character device */
    XDIR	=  4,	/*!< directory */
    BDEV	=  6,	/*!< block device */
    REG		=  8,	/*!< regular file */
    LINK	= 10,	/*!< hard link */
    SOCK	= 12	/*!< socket */
} rpmFileTypes;

/**
 * File States (when installed).
 */
typedef enum rpmfileState_e {
    RPMFILE_STATE_MISSING	= -1,	/* used for unavailable data */
    RPMFILE_STATE_NORMAL 	= 0,
    RPMFILE_STATE_REPLACED 	= 1,
    RPMFILE_STATE_NOTINSTALLED	= 2,
    RPMFILE_STATE_NETSHARED	= 3,
    RPMFILE_STATE_WRONGCOLOR	= 4
} rpmfileState;

#define RPMFILE_IS_INSTALLED(_x) ((_x) == RPMFILE_STATE_NORMAL || (_x) == RPMFILE_STATE_NETSHARED)

/**
 * Exported File Attributes (ie RPMTAG_FILEFLAGS)
 */
enum rpmfileAttrs_e {
    RPMFILE_NONE	= 0,
    RPMFILE_CONFIG	= (1 <<  0),	/*!< from %%config */
    RPMFILE_DOC		= (1 <<  1),	/*!< from %%doc */
    RPMFILE_ICON	= (1 <<  2),	/*!< from %%donotuse. */
    RPMFILE_MISSINGOK	= (1 <<  3),	/*!< from %%config(missingok) */
    RPMFILE_NOREPLACE	= (1 <<  4),	/*!< from %%config(noreplace) */
    RPMFILE_SPECFILE	= (1 <<  5),	/*!< @todo (unnecessary) marks 1st file in srpm. */
    RPMFILE_GHOST	= (1 <<  6),	/*!< from %%ghost */
    RPMFILE_LICENSE	= (1 <<  7),	/*!< from %%license */
    RPMFILE_README	= (1 <<  8),	/*!< from %%readme */
    /* bits 9-10 unused */
    RPMFILE_PUBKEY	= (1 << 11),	/*!< from %%pubkey */
    RPMFILE_ARTIFACT	= (1 << 12),	/*!< from %%artifact */
};

typedef rpmFlags rpmfileAttrs;

#define	RPMFILE_ALL	~(RPMFILE_NONE)

/** \ingroup rpmfiles
 * File disposition(s) during package install/erase transaction.
 */
typedef enum rpmFileAction_e {
    FA_UNKNOWN		= 0,	/*!< initial action for file ... */
    FA_CREATE		= 1,	/*!< ... create from payload. */
    FA_COPYIN		= 2,	/*!< obsolete, unused. */
    FA_COPYOUT		= 3,	/*!< obsolete, unused. */
    FA_BACKUP		= 4,	/*!< ... renamed with ".rpmorig" extension. */
    FA_SAVE		= 5,	/*!< ... renamed with ".rpmsave" extension. */
    FA_SKIP		= 6, 	/*!< ... already replaced, don't remove. */
    FA_ALTNAME		= 7,	/*!< ... create with ".rpmnew" extension. */
    FA_ERASE		= 8,	/*!< ... to be removed. */
    FA_SKIPNSTATE	= 9,	/*!< ... untouched, state "not installed". */
    FA_SKIPNETSHARED	= 10,	/*!< ... untouched, state "netshared". */
    FA_SKIPCOLOR	= 11,	/*!< ... untouched, state "wrong color". */
    FA_TOUCH		= 12,	/*!< ... change metadata only. */
    /* bits 16-31 reserved */
} rpmFileAction;

#define XFA_SKIPPING(_a)	\
    ((_a) == FA_SKIP || (_a) == FA_SKIPNSTATE || (_a) == FA_SKIPNETSHARED || (_a) == FA_SKIPCOLOR)

/**
 * We pass these around as an array with a sentinel.
 */
struct rpmRelocation_s {
    char * oldPath;	/*!< NULL here evals to RPMTAG_DEFAULTPREFIX, */
    char * newPath;	/*!< NULL means to omit the file completely! */
};

enum rpmfiFlags_e {
    RPMFI_NOHEADER		= 0,
    RPMFI_KEEPHEADER		= (1 << 0),
    RPMFI_NOFILECLASS		= (1 << 1),
    RPMFI_NOFILEDEPS		= (1 << 2),
    RPMFI_NOFILELANGS		= (1 << 3),
    RPMFI_NOFILEUSER		= (1 << 4),
    RPMFI_NOFILEGROUP		= (1 << 5),
    RPMFI_NOFILEMODES		= (1 << 6),
    RPMFI_NOFILESIZES		= (1 << 7),
    RPMFI_NOFILECAPS		= (1 << 8),
    RPMFI_NOFILELINKTOS		= (1 << 9),
    RPMFI_NOFILEDIGESTS		= (1 << 10),
    RPMFI_NOFILEMTIMES		= (1 << 11),
    RPMFI_NOFILERDEVS		= (1 << 12),
    RPMFI_NOFILEINODES		= (1 << 13),
    RPMFI_NOFILESTATES		= (1 << 14),
    RPMFI_NOFILECOLORS		= (1 << 15),
    RPMFI_NOFILEVERIFYFLAGS	= (1 << 16),
    RPMFI_NOFILEFLAGS		= (1 << 17),
    RPMFI_NOFILESIGNATURES	= (1 << 18),
};

typedef rpmFlags rpmfiFlags;

#define RPMFI_FLAGS_ERASE \
    (RPMFI_NOFILECLASS | RPMFI_NOFILELANGS | \
     RPMFI_NOFILEMTIMES | RPMFI_NOFILERDEVS | RPMFI_NOFILEINODES | \
     RPMFI_NOFILEVERIFYFLAGS)

#define RPMFI_FLAGS_INSTALL \
    (RPMFI_NOFILECLASS | RPMFI_NOFILEVERIFYFLAGS)

#define RPMFI_FLAGS_VERIFY \
    (RPMFI_NOFILECLASS | RPMFI_NOFILEDEPS | RPMFI_NOFILELANGS | \
     RPMFI_NOFILECOLORS)

#define RPMFI_FLAGS_QUERY \
    (RPMFI_NOFILECLASS | RPMFI_NOFILEDEPS | RPMFI_NOFILELANGS | \
     RPMFI_NOFILECOLORS | RPMFI_NOFILEVERIFYFLAGS)

#define RPMFI_FLAGS_FILETRIGGER \
    (RPMFI_NOFILECLASS | RPMFI_NOFILEDEPS | RPMFI_NOFILELANGS | \
     RPMFI_NOFILEUSER | RPMFI_NOFILEGROUP | RPMFI_NOFILEMODES | \
     RPMFI_NOFILESIZES | RPMFI_NOFILECAPS | RPMFI_NOFILELINKTOS | \
     RPMFI_NOFILEDIGESTS | RPMFI_NOFILEMTIMES | RPMFI_NOFILERDEVS | \
     RPMFI_NOFILEINODES | RPMFI_NOFILECOLORS | \
     RPMFI_NOFILEVERIFYFLAGS | RPMFI_NOFILEFLAGS)

#define RPMFI_FLAGS_ONLY_FILENAMES \
    (RPMFI_FLAGS_FILETRIGGER | RPMFI_NOFILESTATES)

typedef enum rpmFileIter_e {
    RPMFI_ITER_FWD	= 0,
    RPMFI_ITER_BACK	= 1,
    RPMFI_ITER_WRITE_ARCHIVE	= 2,
    RPMFI_ITER_READ_ARCHIVE	= 3,
    RPMFI_ITER_READ_ARCHIVE_CONTENT_FIRST = 4,
    RPMFI_ITER_READ_ARCHIVE_OMIT_HARDLINKS = 5,
    RPMFI_ITER_INTERVAL = 6,
} rpmFileIter;

#define RPMFILEITERMAX 6

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmfiles
 * Create and load a file info set.
 * @param pool		shared string pool (or NULL for private pool)
 * @param h		header
 * @param tagN		unused
 * @param flags		Flags to control what information is loaded.
 * @return		new file info set
 */
rpmfiles rpmfilesNew(rpmstrPool pool, Header h, rpmTagVal tagN, rpmfiFlags flags);

/** \ingroup rpmfiles
 * Reference a file info set instance.
 * @param fi		file info set
 * @return		new file info set reference
 */
rpmfiles rpmfilesLink(rpmfiles fi);

/** \ingroup rpmfiles
 * Destroy a file info set.
 * @param fi		file info set
 * @return		NULL always
 */
rpmfiles rpmfilesFree(rpmfiles fi);

/** \ingroup rpmfiles
 * Return file count from file info set.
 * @param fi		file info set
 * @return		file count
 */
rpm_count_t rpmfilesFC(rpmfiles fi);

/** \ingroup rpmfiles
 * Return directory count from file info set.
 * @param fi		file info set
 * @return		directory count
 */
rpm_count_t rpmfilesDC(rpmfiles fi);

/** \ingroup rpmfiles
 * Return file index of the given file name or -1 if file is not in the rpmfi.
 * The file name may have "." prefixed but is then interpreted as a global
 * path without the prefixing "."
 * @param files         file info set
 * @param fn		file name
 * @return              file index or -1
 */
int rpmfilesFindFN(rpmfiles files, const char * fn);

/** \ingroup rpmfiles
 * Return file index of the given original file name or -1 if file is not
 * in the rpmfi. The file name may have "." prefixed but is then interpreted
 * as a global path without the prefixing "."
 * @param files         file info set
 * @param fn		file name
 * @return              file index or -1
 */
int rpmfilesFindOFN(rpmfiles files, const char * fn);

rpmfi rpmfilesIter(rpmfiles files, int itype);

/** \ingroup rpmfiles
 * Return digest algorithm of a file info set.
 * @param fi		file info set
 * @return		digest algorithm of file info set, 0 on invalid
 */
int rpmfilesDigestAlgo(rpmfiles fi);

/** \ingroup rpmfiles
 * Return union of all file color bits from file info set.
 * @param files		file info set
 * @return		color
 */
rpm_color_t rpmfilesColor(rpmfiles files);

/** \ingroup rpmfiles
 * Return file info comparison.
 * @param afi		1st file info
 * @param aix		index of the 1st file
 * @param bfi		2nd file info
 * @param bix		index of the 2nd file
 * @return		0 if identical
 */
int rpmfilesCompare(rpmfiles afi, int aix, rpmfiles bfi, int bix);

/** \ingroup rpmfiles
 * Return base name from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		base name, NULL on invalid
 */
const char * rpmfilesBN(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return directory name from file info set. Note the index is on
 * distinct directories within the file set, not a file index. The
 * directory index associated with a given file index can be retrieved
 * with rpmfilesDI(). Ie to constuct the full path of file index X
 * you'd catenate the results of rpmfilesDN(f, rpmfilesDI(f, X)) and
 * rpmfilesBN(f, X).
 * @param fi		file info set
 * @param jx		directory index
 * @return		directory, NULL on invalid
 */
const char * rpmfilesDN(rpmfiles fi, int jx);

/** \ingroup rpmfiles
 * Return directory index from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		directory index, -1 on invalid
 */
int rpmfilesDI(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file name from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file name (malloced)
 */
char * rpmfilesFN(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return original directory index from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		directory index, -1 on invalid
 */
int rpmfilesODI(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return original base name from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		base name, NULL on invalid
 */
const char * rpmfilesOBN(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return original directory name from file info set. Note the index is on
 * distinct directories within the file set, not a file index. The
 * directory index associated with a given file index can be retrieved
 * with rpmfilesODI(). Ie to constuct the full path of file index X
 * you'd catenate the results of rpmfilesODN(f, rpmfilesODI(f, X)) and
 * rpmfilesOBN(f, X). 
 * @param fi		file info set
 * @param jx		directory index
 * @return		directory, NULL on invalid
 */
const char * rpmfilesODN(rpmfiles fi, int jx);

/** \ingroup rpmfiles
 * Return original file name from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file name
 */
char * rpmfilesOFN(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file verify flags from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file verify flags, 0 on invalid
 */
rpmVerifyAttrs rpmfilesVFlags(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file state from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file state, 0 on invalid
 */
rpmfileState rpmfilesFState(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file linkto (i.e. symlink(2) target) from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file linkto, NULL on invalid
 */
const char * rpmfilesFLink(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file size from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file size, 0 on invalid
 */
rpm_loff_t rpmfilesFSize(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file color bits from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file color
 */
rpm_color_t rpmfilesFColor(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file class from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file class, 0 on invalid
 */
const char * rpmfilesFClass(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file depends dictionary from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @retval *fddictp	file depends dictionary array (or NULL)
 * @return		no. of file depends entries, 0 on invalid
 */
uint32_t rpmfilesFDepends(rpmfiles fi, int ix, const uint32_t ** fddictp);

/** \ingroup rpmfiles
 * Return (calculated) file nlink count from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file nlink count, 0 on invalid
 */
uint32_t rpmfilesFNlink(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return (calculated) file nlink count from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @param files         returns array of file ids hardlinked including ix,
			NULL for nlink count == 1
 * @return		file nlink count, 0 on invalid
 */
uint32_t rpmfilesFLinks(rpmfiles fi, int ix, const int ** files);

/** \ingroup rpmfiles
 * Return file language(s) from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file language(s), NULL on invalid
 */
const char * rpmfilesFLangs(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file flags from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file flags, 0 on invalid
 */
rpmfileAttrs rpmfilesFFlags(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file mode from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file mode, 0 on invalid
 */
rpm_mode_t rpmfilesFMode(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file (binary) digest of file info set.
 * @param fi		file info set
 * @param ix		file index
 * @retval algo		digest hash algorithm used (pass NULL to ignore)
 * @retval len		digest hash length (pass NULL to ignore)
 * @return		file digest, NULL on invalid
 */
const unsigned char * rpmfilesFDigest(rpmfiles fi, int ix, int *algo, size_t *len);

/** \ingroup rpmfiles
 * Return file (binary) digest of file info set.
 * @param fi            file info set
 * @param ix            file index
 * @retval len       signature length (pass NULL to ignore)
 * @return              file signature, NULL on invalid
 */
const unsigned char * rpmfilesFSignature(rpmfiles fi, int ix, size_t *len);

/** \ingroup rpmfiles
 * Return file rdev from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file rdev, 0 on invalid
 */
rpm_rdev_t rpmfilesFRdev(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file inode from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file inode, 0 on invalid
 */
rpm_ino_t rpmfilesFInode(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file modify time from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file modify time, 0 on invalid
 */
rpm_time_t rpmfilesFMtime(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file owner from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file owner, NULL on invalid
 */
const char * rpmfilesFUser(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return file group from file info set.
 * @param fi		file info set
 * @param ix		file index
 * @return		file group, NULL on invalid
 */
const char * rpmfilesFGroup(rpmfiles fi, int ix);

/** \ingroup rpmfiles
 * Return textual representation of file capabilities 
 * from file info set. See cap_from_text(3) for details.
 * @param fi		file info set
 * @param ix		file index
 * @return		file capability description, "" for no capabilities
 * 			and NULL on invalid
 */
const char * rpmfilesFCaps(rpmfiles fi, int ix);

/** \ingroup rpmfi
 * Map file stat(2) info.
 * @param fi		file info set
 * @param ix		file index
 * @param flags		flags
 * @retval sb		mapped stat(2) data
 * @return		0 on success
 */
int rpmfilesStat(rpmfiles fi, int ix, int flags, struct stat *sb);

/** \ingroup rpmfiles
 * Verify file attributes (including digest).
 * @param fi		file info set
 * @param ix		file index
 * @param omitMask	bit(s) to disable verify checks
 * @return		bit(s) to indicate failure (ie 0 for passed verify)
 */
rpmVerifyAttrs rpmfilesVerify(rpmfiles fi, int ix, rpmVerifyAttrs omitMask);

#ifdef __cplusplus
}
#endif

#endif /* _RPMFILES_H */
