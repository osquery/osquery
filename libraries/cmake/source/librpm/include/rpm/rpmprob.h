#ifndef _RPMPROB_H
#define _RPMPROB_H

/** \ingroup rpmprob
 * \file lib/rpmprob.h
 * Structures and prototypes used for an rpm problem item.
 */

#include <stdio.h>
#include <rpm/rpmtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rpmProblem_s * rpmProblem;

/** \ingroup rpmprob
 * @todo Generalize filter mechanism.
 */
enum rpmprobFilterFlags_e {
    RPMPROB_FILTER_NONE		= 0,
    RPMPROB_FILTER_IGNOREOS	= (1 << 0),	/*!< from --ignoreos */
    RPMPROB_FILTER_IGNOREARCH	= (1 << 1),	/*!< from --ignorearch */
    RPMPROB_FILTER_REPLACEPKG	= (1 << 2),	/*!< from --replacepkgs */
    RPMPROB_FILTER_FORCERELOCATE= (1 << 3),	/*!< from --badreloc */
    RPMPROB_FILTER_REPLACENEWFILES= (1 << 4),	/*!< from --replacefiles */
    RPMPROB_FILTER_REPLACEOLDFILES= (1 << 5),	/*!< from --replacefiles */
    RPMPROB_FILTER_OLDPACKAGE	= (1 << 6),	/*!< from --oldpackage */
    RPMPROB_FILTER_DISKSPACE	= (1 << 7),	/*!< from --ignoresize */
    RPMPROB_FILTER_DISKNODES	= (1 << 8)	/*!< from --ignoresize */
};

typedef rpmFlags rpmprobFilterFlags;

/** \ingroup rpmprob
 * Enumerate transaction set problem types.
 */
typedef enum rpmProblemType_e {
    RPMPROB_BADARCH,	/*!< package ... is for a different architecture */
    RPMPROB_BADOS,	/*!< package ... is for a different operating system */
    RPMPROB_PKG_INSTALLED, /*!< package ... is already installed */
    RPMPROB_BADRELOCATE,/*!< path ... is not relocatable for package ... */
    RPMPROB_REQUIRES,	/*!< package ... has unsatisfied Requires: ... */
    RPMPROB_CONFLICT,	/*!< package ... has unsatisfied Conflicts: ... */
    RPMPROB_NEW_FILE_CONFLICT, /*!< file ... conflicts between attempted installs of ... */
    RPMPROB_FILE_CONFLICT,/*!< file ... from install of ... conflicts with file from package ... */
    RPMPROB_OLDPACKAGE,	/*!< package ... (which is newer than ...) is already installed */
    RPMPROB_DISKSPACE,	/*!< installing package ... needs ... on the ... filesystem */
    RPMPROB_DISKNODES,	/*!< installing package ... needs ... on the ... filesystem */
    RPMPROB_OBSOLETES,	/*!< package ... is obsoleted by ... */
 } rpmProblemType;

/** \ingroup rpmprob
 * Create a problem item.
 * @param type		type of problem
 * @param pkgNEVR	package name
 * @param key		filename or python object address
 * @param altNEVR	related (e.g. through a dependency) package name
 * @param str		generic string attribute
 * @param number	generic number attribute
 * @return		rpmProblem
 */
rpmProblem rpmProblemCreate(rpmProblemType type,
                            const char * pkgNEVR, fnpyKey key,
                            const char * altNEVR,
                            const char * str, uint64_t number);

/** \ingroup rpmprob
 * Destroy a problem item.
 * @param prob		rpm problem
 * @return		rpm problem (NULL)
 */
rpmProblem rpmProblemFree(rpmProblem prob);

/** \ingroup rpmprob
 * Reference an rpmProblem instance
 * @param prob		rpm problem
 * @return		rpm problem
 */
rpmProblem rpmProblemLink(rpmProblem prob);

/** \ingroup rpmprob
 * Compare two problems for equality.
 * @param ap		1st problem
 * @param bp		2nd problem
 * @return		1 if the problems differ, 0 otherwise
 */
int rpmProblemCompare(rpmProblem ap, rpmProblem bp);

/** \ingroup rpmprob
 * Return package NEVR
 * @param prob		rpm problem
 * @return		package NEVR
 */

const char * rpmProblemGetPkgNEVR(rpmProblem prob);
/** \ingroup rpmprob
 * Return related (e.g. through a dependency) package NEVR
 * @param prob		rpm problem
 * @return		related (e.g. through a dependency) package NEVR
 */
const char * rpmProblemGetAltNEVR(rpmProblem prob);

/** \ingroup rpmprob
 * Return type of problem (dependency, diskpace etc)
 * @param prob		rpm problem
 * @return		type of problem
 */

rpmProblemType rpmProblemGetType(rpmProblem prob);

/** \ingroup rpmprob
 * Return filename or python object address of a problem
 * @param prob		rpm problem
 * @return		filename or python object address
 */
fnpyKey rpmProblemGetKey(rpmProblem prob);

/** \ingroup rpmprob
 * Return a generic data string from a problem
 * @param prob		rpm problem
 * @return		a generic data string
 * @todo		needs a better name
 */
const char * rpmProblemGetStr(rpmProblem prob);

/** \ingroup rpmprob
 * Return disk requirement (needed disk space / number of inodes)
 * depending on problem type. On problem types other than RPMPROB_DISKSPACE
 * and RPMPROB_DISKNODES return value is undefined.
 * @param prob		rpm problem
 * @return		disk requirement
 */
rpm_loff_t rpmProblemGetDiskNeed(rpmProblem prob);

/** \ingroup rpmprob
 * Return formatted string representation of a problem.
 * @param prob		rpm problem
 * @return		formatted string (malloc'd)
 */
char * rpmProblemString(rpmProblem prob);

#ifdef __cplusplus
}
#endif

#endif	/* _RPMPROB_H */
