#ifndef _H_SPEC_
#define _H_SPEC_

/** \ingroup rpmbuild
 * \file build/rpmspec.h
 *  The rpmSpec and Package data structures used during build.
 */

#include <rpm/rpmstring.h>	/* StringBuf */
#include <rpm/rpmcli.h>	/* for QVA_t */

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmbuild
 */
typedef struct Package_s * rpmSpecPkg;
typedef struct Source * rpmSpecSrc;
typedef struct rpmSpecIter_s * rpmSpecPkgIter;
typedef struct rpmSpecIter_s * rpmSpecSrcIter;

enum rpmSourceFlags_e {
    RPMBUILD_ISSOURCE	= (1 << 0),
    RPMBUILD_ISPATCH	= (1 << 1),
    RPMBUILD_ISICON	= (1 << 2),
    RPMBUILD_ISNO	= (1 << 3),
};

typedef rpmFlags rpmSourceFlags;

#define RPMBUILD_DEFAULT_LANG "C"

enum rpmSpecFlags_e {
    RPMSPEC_NONE	= 0,
    RPMSPEC_ANYARCH	= (1 << 0),
    RPMSPEC_FORCE	= (1 << 1),
    RPMSPEC_NOLANG	= (1 << 2),
    RPMSPEC_NOUTF8	= (1 << 3),
};

typedef rpmFlags rpmSpecFlags;

/** \ingroup rpmbuild
 * Destroy Spec structure.
 * @param spec		spec file control structure
 * @return		NULL always
 */
rpmSpec rpmSpecFree(rpmSpec spec);

/* Iterator for spec packages */
rpmSpecPkgIter rpmSpecPkgIterInit(rpmSpec spec);
rpmSpecPkg rpmSpecPkgIterNext(rpmSpecPkgIter iter);
rpmSpecPkgIter rpmSpecPkgIterFree(rpmSpecPkgIter iter);

/* Getters for spec package attributes */
Header rpmSpecPkgHeader(rpmSpecPkg pkg);

/*
 * Retrieve package specific parsed spec script section (RPMBUILD_FILE_LIST,
 * RPMBUILD_FILE_FILE, RPMBUILD_POLICY) as a malloc'ed string.
 */
char * rpmSpecPkgGetSection(rpmSpecPkg pkg, int section);


/* Iterator for spec sources */
rpmSpecSrcIter rpmSpecSrcIterInit(rpmSpec spec);
rpmSpecSrc rpmSpecSrcIterNext(rpmSpecSrcIter iter);
rpmSpecSrcIter rpmSpecSrcIterFree(rpmSpecSrcIter iter);

/* Getters for spec source attributes */
rpmSourceFlags rpmSpecSrcFlags(rpmSpecSrc src);
int rpmSpecSrcNum(rpmSpecSrc src);
const char * rpmSpecSrcFilename(rpmSpecSrc src, int full);

/*
 * Retrieve parsed spec script section (RPMBUILD_PREP, RPMBUILD_BUILD etc).
 * As a special case, RPMBUILD_NONE as section returns the entire spec in
 * preprocessed (macros expanded etc) format.
 */
const char * rpmSpecGetSection(rpmSpec spec, int section);

/** \ingroup rpmbuild
 * Function to query spec file(s).
 * @param ts		transaction set
 * @param qva		parsed query/verify options
 * @param arg		query argument
 * @return		0 on success, else no. of failures
 */
int rpmspecQuery(rpmts ts, QVA_t qva, const char * arg);

#ifdef __cplusplus
}
#endif

#endif /* _H_SPEC_ */
