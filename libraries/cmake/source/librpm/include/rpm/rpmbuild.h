#ifndef	_H_RPMBUILD_
#define	_H_RPMBUILD_

/** \ingroup rpmbuild
 * \file build/rpmbuild.h
 *  This is the *only* module users of librpmbuild should need to include.
 */

#include <rpm/rpmcli.h>
#include <rpm/rpmds.h>
#include <rpm/rpmspec.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmbuild
 * Bit(s) to control rpmSpecBuild() operation. Also used as argument to
 * rpmSpecGetSection and rpmSpecPkgGetSection.
 */
enum rpmBuildFlags_e {
    RPMBUILD_NONE	= 0,
    RPMBUILD_PREP	= (1 <<  0),	/*!< Execute %%prep. */
    RPMBUILD_BUILD	= (1 <<  1),	/*!< Execute %%build. */
    RPMBUILD_INSTALL	= (1 <<  2),	/*!< Execute %%install. */
    RPMBUILD_CHECK	= (1 <<  3),	/*!< Execute %%check. */
    RPMBUILD_CLEAN	= (1 <<  4),	/*!< Execute %%clean. */
    RPMBUILD_FILECHECK	= (1 <<  5),	/*!< Check %%files manifest. */
    RPMBUILD_PACKAGESOURCE = (1 <<  6),	/*!< Create source package. */
    RPMBUILD_PACKAGEBINARY = (1 <<  7),	/*!< Create binary package(s). */
    RPMBUILD_RMSOURCE	= (1 <<  8),	/*!< Remove source(s) and patch(s). */
    RPMBUILD_RMBUILD	= (1 <<  9),	/*!< Remove build sub-tree. */
    RPMBUILD_STRINGBUF	= (1 << 10),	/*!< Internal use only */
    RPMBUILD_RMSPEC	= (1 << 11),	/*!< Remove spec file. */
    RPMBUILD_FILE_FILE  = (1 << 16),    /*!< rpmSpecPkgGetSection: %files -f */
    RPMBUILD_FILE_LIST  = (1 << 17),    /*!< rpmSpecPkgGetSection: %files */
    RPMBUILD_POLICY     = (1 << 18),    /*!< rpmSpecPkgGetSection: %policy */

    RPMBUILD_NOBUILD	= (1 << 31)	/*!< Don't execute or package. */
};

typedef rpmFlags rpmBuildFlags;

/** \ingroup rpmbuild
 * Bit(s) to control package generation
 */
enum rpmBuildPkgFlags_e {
    RPMBUILD_PKG_NONE		= 0,
    RPMBUILD_PKG_NODIRTOKENS	= (1 << 0), /*!< Legacy filename layout */
};

typedef rpmFlags rpmBuildPkgFlags;

/** \ingroup rpmbuild
 * Describe build request.
 */
struct rpmBuildArguments_s {
    rpmBuildPkgFlags pkgFlags;	/*!< Bit(s) to control package generation. */
    rpmBuildFlags buildAmount;	/*!< Bit(s) to control build execution. */
    char * buildRootOverride; 	/*!< from --buildroot */
    char * cookie;		/*!< NULL for binary, ??? for source, rpm's */
    const char * rootdir;
};

/** \ingroup rpmbuild
 */
typedef	struct rpmBuildArguments_s *	BTA_t;

/** \ingroup rpmbuild
 * Parse spec file into spec control structure.
 * @todo Eliminate buildRoot from here, its a build, not spec property
 *
 * @param specFile	path to spec file
 * @param flags		flags to control operation
 * @param buildRoot	buildRoot override or NULL for default
 * @return		new spec control structure
 */
rpmSpec rpmSpecParse(const char *specFile, rpmSpecFlags flags,
		     const char *buildRoot);

/** \ingroup rpmbuild
 * Return the headers of the SRPM that would be built from the spec file
 * @param spec		path to spec file
 * @return		Header
 */
Header rpmSpecSourceHeader(rpmSpec spec);

/** \ingroup rpmbuild
 * Verify build depencies of a spec against.
 * @param ts		(empty) transaction set
 * @param spec		parsed spec control structure
 * @return		rpm problem set or NULL on no problems
 */
rpmps rpmSpecCheckDeps(rpmts ts, rpmSpec spec);

/** \ingroup rpmbuild
 * Retrieve build dependency set from spec.
 * @param spec		parsed spec control structure
 * @param tag		dependency tag
 * @return		dependency set of tag (or NULL)
 */
rpmds rpmSpecDS(rpmSpec spec, rpmTagVal tag);

/** \ingroup rpmbuild
 * Spec build stages state machine driver.
 * @param spec		spec file control structure
 * @param buildArgs	build arguments
 * @return		RPMRC_OK on success
 */
rpmRC rpmSpecBuild(rpmSpec spec, BTA_t buildArgs);

#ifdef __cplusplus
}
#endif

#endif	/* _H_RPMBUILD_ */
