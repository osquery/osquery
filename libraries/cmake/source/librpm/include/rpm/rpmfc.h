#ifndef _H_RPMFC_
#define _H_RPMFC_

/** \ingroup rpmfc rpmbuild
 * \file build/rpmfc.h
 * Structures and methods for build-time file classification.
 */

#include <rpm/rpmtypes.h>
#include <rpm/argv.h>	/* for ARGV_t */
#include <rpm/rpmspec.h>	/* for Package */

#ifdef __cplusplus
extern "C" {
#endif

extern int _rpmfc_debug;

/** \ingroup rpmfc
 */
typedef struct rpmfc_s * rpmfc;

/** \ingroup rpmfc
 */
enum FCOLOR_e {
    RPMFC_BLACK			= 0,
    RPMFC_ELF32			= (1 <<  0),
    RPMFC_ELF64			= (1 <<  1),
    RPMFC_ELFMIPSN32		= (1 <<  2),
#define	RPMFC_ELF	(RPMFC_ELF32|RPMFC_ELF64|RPMFC_ELFMIPSN32)
	/* (1 << 3) leaks into package headers, reserved */

    RPMFC_WHITE			= (1 << 29),
    RPMFC_INCLUDE		= (1 << 30),
    RPMFC_ERROR			= (1 << 31)
};

/** \ingroup rpmfc
 */
typedef	rpmFlags FCOLOR_t;

/** \ingroup rpmfc
 */
typedef const struct rpmfcTokens_s * rpmfcToken;

/** \ingroup rpmfc
 * Print results of file classification.
 * @param msg		message prefix (NULL for none)
 * @param fc		file classifier
 * @param fp		output file handle (NULL for stderr)
 */
void rpmfcPrint(const char * msg, rpmfc fc, FILE * fp);

/** \ingroup rpmfc
 * Destroy a file classifier.
 * @param fc		file classifier
 * @return		NULL always
 */
rpmfc rpmfcFree(rpmfc fc);

/** \ingroup rpmfc
 * Create a file classifier.
 * @param rootDir	(build) root directory
 * @param flags		(unused)
 * @return		new file classifier
 */
rpmfc rpmfcCreate(const char *rootDir, rpmFlags flags);

/** \ingroup rpmfc
 * @deprecated
 * Create a file classifier.
 * @return		new file classifier
 */
RPM_GNUC_DEPRECATED
rpmfc rpmfcNew(void);


/** \ingroup rpmfc
 * Build file class dictionary and mappings.
 * @param fc		file classifier
 * @param argv		files to classify
 * @param fmode		files mode_t array (or NULL)
 * @return		RPMRC_OK on success
 */
rpmRC rpmfcClassify(rpmfc fc, ARGV_t argv, rpm_mode_t * fmode);

/** \ingroup rpmfc
 * Build file/package dependency dictionary and mappings.
 * @param fc		file classifier
 * @return		RPMRC_OK on success
 */
rpmRC rpmfcApply(rpmfc fc);

/** \ingroup rpmfc
 * Retrieve file classification provides
 * @param fc		file classifier
 * @return		rpmds dependency set of fc provides
 */
rpmds rpmfcProvides(rpmfc fc);

/** \ingroup rpmfc
 * Retrieve file classification requires
 * @param fc		file classifier
 * @return		rpmds dependency set of fc requires
 */
rpmds rpmfcRequires(rpmfc fc);

/** \ingroup rpmfc
 * Retrieve file classification recommends
 * @param fc		file classifier
 * @return		rpmds dependency set of fc recommends
 */
rpmds rpmfcRecommends(rpmfc fc);

/** \ingroup rpmfc
 * Retrieve file classification suggests
 * @param fc		file classifier
 * @return		rpmds dependency set of fc suggests
 */
rpmds rpmfcSuggests(rpmfc fc);

/** \ingroup rpmfc
 * Retrieve file classification supplements
 * @param fc		file classifier
 * @return		rpmds dependency set of fc supplements
 */
rpmds rpmfcSupplements(rpmfc fc);

/** \ingroup rpmfc
 * Retrieve file classification enhances
 * @param fc		file classifier
 * @return		rpmds dependency set of fc enhances
 */
rpmds rpmfcEnhances(rpmfc fc);

/** \ingroup rpmfc
 * Retrieve file classification conflicts
 * @param fc		file classifier
 * @return		rpmds dependency set of fc conflicts
 */
rpmds rpmfcConflicts(rpmfc fc);

/** \ingroup rpmfc
 * Retrieve file classification obsoletes
 * @param fc		file classifier
 * @return		rpmds dependency set of fc obsoletes
 */
rpmds rpmfcObsoletes(rpmfc fc);

/** \ingroup rpmfc
 * Retrieve file classification dependencies
 * @param fc		file classifier
 * @param tagN		name tag of the wanted dependency
 * @return		rpmds dependency set of fc requires
 */
rpmds rpmfcDependencies(rpmfc fc, rpmTagVal tagN);

#ifdef __cplusplus
}
#endif

#endif /* _H_RPMFC_ */
