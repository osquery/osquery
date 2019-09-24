#ifndef H_RPMFI
#define H_RPMFI

/** \ingroup rpmfi
 * \file lib/rpmfi.h
 * File info set iterator API.
 */

#include <rpm/rpmtypes.h>
#include <rpm/rpmfiles.h>
#include <rpm/rpmarchive.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmfi
 * Reference a file info set iterator instance.
 * @param fi		file info set iterator
 * @return		new file info set iterator reference
 */
rpmfi rpmfiLink (rpmfi fi);

/** \ingroup rpmfi
 * Return file count from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file count
 */
rpm_count_t rpmfiFC(rpmfi fi);

/** \ingroup rpmfi
 * Return current file index from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file index
 */
int rpmfiFX(rpmfi fi);

/** \ingroup rpmfi
 * Set current file index in file info set iterator.
 * @param fi		file info set iterator
 * @param fx		new file index
 * @return		current file index
 */
int rpmfiSetFX(rpmfi fi, int fx);

/** \ingroup rpmfi
 * Return directory count from file info set iterator.
 * @param fi		file info set iterator
 * @return		current directory count
 */
rpm_count_t rpmfiDC(rpmfi fi);

/** \ingroup rpmfi
 * Return current directory index from file info set iterator.
 * @param fi		file info set iterator
 * @return		current directory index
 */
int rpmfiDX(rpmfi fi);

/** \ingroup rpmfi
 * Set current directory index in file info set iterator.
 * @param fi		file info set iterator
 * @param dx		new directory index
 * @return		current directory index
 */
int rpmfiSetDX(rpmfi fi, int dx);

/** \ingroup rpmfi
 * Return current base name from file info set iterator.
 * @param fi		file info set iterator
 * @return		current base name, NULL on invalid
 */
const char * rpmfiBN(rpmfi fi);

/** \ingroup rpmfi
 * Return current directory name from file info set iterator.
 * @param fi		file info set iterator
 * @return		current directory, NULL on invalid
 */
const char * rpmfiDN(rpmfi fi);

/** \ingroup rpmfi
 * Return current file name from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file name
 */
const char * rpmfiFN(rpmfi fi);

/** \ingroup rpmfi
 * Return file index of the given file name or -1 if file is not in the rpmfi.
 * The file name may have "." prefixed but is then interpreted as a global
 * path without the prefixing "."
 * @param fi            file info set iterator
 * @param fn		file name
 * @return              file index or -1
 */
int rpmfiFindFN(rpmfi fi, const char * fn);

/** \ingroup rpmfi
 * Return current original base name from file info set iterator.
 * @param fi		file info set iterator
 * @return		current base name, NULL on invalid
 */
const char * rpmfiOBN(rpmfi fi);

/** \ingroup rpmfi
 * Return current original directory name from file info set iterator.
 * @param fi		file info set iterator
 * @return		current directory, NULL on invalid
 */
const char * rpmfiODN(rpmfi fi);

/** \ingroup rpmfi
 * Return current original file name from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file name
 */
const char * rpmfiOFN(rpmfi fi);

/** \ingroup rpmfi
 * Return file index of the given original file name or -1 if file is not
 * in the rpmfi. The file name may have "." prefixed but is then interpreted
 * as a global path without the prefixing "."
 * @param fi            file info set iterator
 * @param fn		file name
 * @return              file index or -1
 */
int rpmfiFindOFN(rpmfi fi, const char * fn);

/** \ingroup rpmfi
 * Return current file flags from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file flags, 0 on invalid
 */
rpmfileAttrs rpmfiFFlags(rpmfi fi);

/** \ingroup rpmfi
 * Return current file verify flags from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file verify flags, 0 on invalid
 */
rpmVerifyAttrs rpmfiVFlags(rpmfi fi);

/** \ingroup rpmfi
 * Return current file mode from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file mode, 0 on invalid
 */
rpm_mode_t rpmfiFMode(rpmfi fi);

/** \ingroup rpmfi
 * Return current file state from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file state, 0 on invalid
 */
rpmfileState rpmfiFState(rpmfi fi);

/** \ingroup rpmfi
 * Return digest algorithm of a file info set iterator.
 * @param fi		file info set iterator
 * @return		digest algorithm of file info set iterator, 0 on invalid
 */
int rpmfiDigestAlgo(rpmfi fi);

/** \ingroup rpmfi
 * Return current file (binary) digest of file info set iterator.
 * @param fi		file info set iterator
 * @retval algo		digest hash algorithm used (pass NULL to ignore)
 * @retval diglen	digest hash length (pass NULL to ignore)
 * @return		current file digest, NULL on invalid
 */
const unsigned char * rpmfiFDigest(rpmfi fi, int *algo, size_t *diglen);

/** \ingroup rpmfi
 * Return current file (hex) digest of file info set iterator.
 * The file info set iterator stores file digests in binary format to conserve
 * memory, this converts the binary data back to hex presentation used in
 * headers. 
 * @param fi		file info set iterator
 * @retval algo		digest hash algorithm used (pass NULL to ignore)
 * @return		current file digest (malloc'ed), NULL on invalid
 */
char * rpmfiFDigestHex(rpmfi fi, int *algo);

/** \ingroup rpmfi
 * Return current file (binary) signature of file info set iterator.
 * @param fi		file info set iterator
 * @retval siglen	signature length (pass NULL to ignore)
 * @return		current file signature, NULL on invalid
 */
const unsigned char * rpmfiFSignature(rpmfi fi, size_t *siglen);

/** \ingroup rpmfi
 * Return current file linkto (i.e. symlink(2) target) from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file linkto, NULL on invalid
 */
const char * rpmfiFLink(rpmfi fi);

/** \ingroup rpmfi
 * Return current file size from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file size, 0 on invalid
 */
rpm_loff_t rpmfiFSize(rpmfi fi);

/** \ingroup rpmfi
 * Return current file rdev from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file rdev, 0 on invalid
 */
rpm_rdev_t rpmfiFRdev(rpmfi fi);

/** \ingroup rpmfi
 * Return current file inode from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file inode, 0 on invalid
 */
rpm_ino_t rpmfiFInode(rpmfi fi);

/** \ingroup rpmfi
 * Return union of all file color bits from file info set iterator.
 * @param fi		file info set iterator
 * @return		current color
 */
rpm_color_t rpmfiColor(rpmfi fi);

/** \ingroup rpmfi
 * Return current file color bits from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file color
 */
rpm_color_t rpmfiFColor(rpmfi fi);

/** \ingroup rpmfi
 * Return current file class from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file class, 0 on invalid
 */
const char * rpmfiFClass(rpmfi fi);

/** \ingroup rpmfi
 * Return current file depends dictionary from file info set iterator.
 * @param fi		file info set iterator
 * @retval *fddictp	file depends dictionary array (or NULL)
 * @return		no. of file depends entries, 0 on invalid
 */
uint32_t rpmfiFDepends(rpmfi fi,
		const uint32_t ** fddictp);

/** \ingroup rpmfi
 * Return (calculated) current file nlink count from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file nlink count, 0 on invalid
 */
uint32_t rpmfiFNlink(rpmfi fi);


/** \ingroup rpmfi
 * Return (calculated) current file nlink count from file info set iterator.
 * @param fi		file info set iterator
 * @param files         returns array of file ids hardlinked including ix,
			NULL for nlink count == 1
 * @return		current file nlink count, 0 on invalid
 */
uint32_t rpmfiFLinks(rpmfi fi, const int ** files);

/** \ingroup rpmfi
 * Return current file modify time from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file modify time, 0 on invalid
 */
rpm_time_t rpmfiFMtime(rpmfi fi);

/** \ingroup rpmfi
 * Return current file owner from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file owner, NULL on invalid
 */
const char * rpmfiFUser(rpmfi fi);

/** \ingroup rpmfi
 * Return current file group from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file group, NULL on invalid
 */
const char * rpmfiFGroup(rpmfi fi);

/** \ingroup rpmfi
 * Return textual representation of current file capabilities 
 * from file info set iterator. See cap_from_text(3) for details.
 * @param fi		file info set iterator
 * @return		file capability description, "" for no capabilities
 * 			and NULL on invalid
 */
const char * rpmfiFCaps(rpmfi fi);

/** \ingroup rpmfi
 * Return current file language(s) from file info set iterator.
 * @param fi		file info set iterator
 * @return		current file language(s), NULL on invalid
 */
const char * rpmfiFLangs(rpmfi fi);

/** \ingroup rpmfi
 * Map file stat(2) info.
 * @param fi		file info iterator
 * @param flags		flags
 * @retval sb		mapped stat(2) data
 */
int rpmfiStat(rpmfi fi, int flags, struct stat *sb);

/** \ingroup rpmfi
 * Return next file iterator index.
 * @param fi		file info set iterator
 * @return		file iterator index, -1 on termination
 */
int rpmfiNext(rpmfi fi);

/** \ingroup rpmfi
 * Initialize file iterator index.
 * @param fi		file info set iterator
 * @param fx		file iterator index
 * @return		file info set iterator
 */
rpmfi rpmfiInit(rpmfi fi, int fx);

/** \ingroup rpmfi
 * Return next directory iterator index.
 * @param fi		file info set iterator
 * @return		directory iterator index, -1 on termination
 */
int rpmfiNextD(rpmfi fi);

/** \ingroup rpmfi
 * Initialize directory iterator index.
 * @param fi		file info set iterator
 * @param dx		directory iterator index
 * @return		file info set iterator, NULL if dx is out of range
 */
rpmfi rpmfiInitD(rpmfi fi, int dx);

/** \ingroup rpmfi
 * Destroy a file info set iterator.
 * @param fi		file info set iterator
 * @return		NULL always
 */
rpmfi rpmfiFree(rpmfi fi);

/** \ingroup rpmfi
 * Create and load a file info set iterator.
 * @param pool		shared string pool (or NULL for private pool)
 * @param h		header
 * @param tagN		unused
 * @param flags		Flags to control what information is loaded.
 * @return		new file info set iterator
 */
rpmfi rpmfiNewPool(rpmstrPool pool, Header h, rpmTagVal tagN, rpmfiFlags flags);

/** \ingroup rpmfi
 * Create and load a file info set iterator.
 * @param ts		unused
 * @param h		header
 * @param tagN		unused
 * @param flags		Flags to control what information is loaded.
 * @return		new file info set iterator
 */
rpmfi rpmfiNew(const rpmts ts, Header h, rpmTagVal tagN, rpmfiFlags flags);

/** \ingroup rpmfi
 * Return file type from mode_t.
 * @param mode		file mode bits (from header)
 * @return		file type
 */
rpmFileTypes rpmfiWhatis(rpm_mode_t mode);

/** \ingroup rpmfi
 * Return file info comparison.
 * @param afi		1st file info
 * @param bfi		2nd file info
 * @return		0 if identical
 */
int rpmfiCompare(const rpmfi afi, const rpmfi bfi);

/** \ingroup rpmfi
 * Verify file attributes (including digest).
 * @param fi		file info iterator
 * @param omitMask	bit(s) to disable verify checks
 * @return		bit(s) to indicate failure (ie 0 for passed verify)
 */
rpmVerifyAttrs rpmfiVerify(rpmfi fi, rpmVerifyAttrs omitMask);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMDS */
