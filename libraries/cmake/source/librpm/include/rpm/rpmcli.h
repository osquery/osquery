#ifndef H_RPMCLI
#define	H_RPMCLI

/** \ingroup rpmcli rpmbuild
 * \file lib/rpmcli.h
 *
 * Parsing RPM command line arguments
 */

#include <popt.h>

#include <rpm/rpmlib.h>
#include <rpm/rpmurl.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmcallback.h>
#include <rpm/rpmts.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmvf.h>
#include <rpm/argv.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmcli
 * Popt option table for options shared by all modes and executables.
 */
extern struct poptOption		rpmcliAllPoptTable[];

extern const char * rpmcliPipeOutput;

extern const char * rpmcliRcfile;

extern const char * rpmcliRootDir;

/** \ingroup rpmcli
 * Initialize most everything needed by an rpm CLI executable context.
 * @param argc			no. of args
 * @param argv			arg array
 * @param optionsTable		popt option table
 * @return			popt context (or NULL)
 */
poptContext
rpmcliInit(int argc, char *const argv[], struct poptOption * optionsTable);

/** \ingroup rpmcli
 * Make sure that rpm configuration has been read.
 * @warning Options like --rcfile and --verbose must precede callers option.
 */
void rpmcliConfigured(void);

/** \ingroup rpmcli
 * Destroy most everything needed by an rpm CLI executable context.
 * @param optCon		popt context
 * @return			NULL always
 */
poptContext
rpmcliFini(poptContext optCon);

/**
 * Common/global popt tokens used for command line option tables.
 */
#define	RPMCLI_POPT_NODEPS		-1025
#define	RPMCLI_POPT_FORCE		-1026
#define	RPMCLI_POPT_NOMD5		-1027
#define	RPMCLI_POPT_NOFILEDIGEST	-1027	/* same as obsolete RPMCLI_POPT_NOMD5 */
#define	RPMCLI_POPT_NOSCRIPTS		-1028
#define	RPMCLI_POPT_NOSIGNATURE		-1029
#define	RPMCLI_POPT_NODIGEST		-1030
#define	RPMCLI_POPT_NOHDRCHK		-1031
#define	RPMCLI_POPT_NOCONTEXTS		-1032
#define	RPMCLI_POPT_NOCAPS		-1033
#define	RPMCLI_POPT_TARGETPLATFORM	-1034

/* ==================================================================== */
/** \name RPMQV */

/** \ingroup rpmcli
 * Query/Verify argument qualifiers.
 * @todo Reassign to tag values.
 */
enum rpmQVSources_e {
    RPMQV_PACKAGE = 0,	/*!< ... from package name db search. */
    RPMQV_PATH,		/*!< ... from file path db search. */
    RPMQV_ALL,		/*!< ... from each installed package. */
    RPMQV_RPM, 		/*!< ... from reading binary rpm package. */
    RPMQV_GROUP,	/*!< ... from group db search. */
    RPMQV_WHATPROVIDES,	/*!< ... from provides db search. */
    RPMQV_WHATREQUIRES,	/*!< ... from requires db search. */
    RPMQV_TRIGGEREDBY,	/*!< ... from trigger db search. */
    RPMQV_DBOFFSET,	/*!< ... from database header instance. */
    RPMQV_SPECRPMS,	/*!< ... from spec file binaries (query only). */
    RPMQV_SPECFILE = RPMQV_SPECRPMS, /*!< ... backwards compatibility */
    RPMQV_PKGID,	/*!< ... from package id (header+payload MD5). */
    RPMQV_HDRID,	/*!< ... from header id (immutable header SHA1). */
    RPMQV_TID,		/*!< ... from install transaction id (time stamp). */
    RPMQV_SPECSRPM,	/*!< ... from spec file source (query only). */
    RPMQV_WHATRECOMMENDS,	/*!< ... from recommends db search. */
    RPMQV_WHATSUGGESTS,		/*!< ... from suggests db search. */
    RPMQV_WHATSUPPLEMENTS,	/*!< ... from supplements db search. */
    RPMQV_WHATENHANCES,		/*!< ... from enhances db search. */
    RPMQV_SPECBUILTRPMS,	/*!< ... from pkgs which would be built from spec */
};

typedef rpmFlags rpmQVSources;

/** \ingroup rpmcli
 * Bit(s) to control rpmQuery() operation, stored in qva_flags.
 * @todo Merge rpmQueryFlags, rpmVerifyFlags, and rpmVerifyAttrs?.
 */
enum rpmQueryFlags_e {
    QUERY_FOR_DEFAULT	= 0,		/*!< */
    QUERY_MD5		= (1 << 0),	/*!< from --nomd5 */
    QUERY_FILEDIGEST	= (1 << 0),	/*!< from --nofiledigest, same as --nomd5 */
    QUERY_SIZE		= (1 << 1),	/*!< from --nosize */
    QUERY_LINKTO	= (1 << 2),	/*!< from --nolink */
    QUERY_USER		= (1 << 3),	/*!< from --nouser) */
    QUERY_GROUP		= (1 << 4),	/*!< from --nogroup) */
    QUERY_MTIME		= (1 << 5),	/*!< from --nomtime) */
    QUERY_MODE		= (1 << 6),	/*!< from --nomode) */
    QUERY_RDEV		= (1 << 7),	/*!< from --nodev */
	/* bits 8-14 unused, reserved for rpmVerifyAttrs */
    QUERY_CONTEXTS	= (1 << 15),	/*!< verify: from --nocontexts */
    QUERY_FILES		= (1 << 16),	/*!< verify: from --nofiles */
    QUERY_DEPS		= (1 << 17),	/*!< verify: from --nodeps */
    QUERY_SCRIPT	= (1 << 18),	/*!< verify: from --noscripts */
    QUERY_DIGEST	= (1 << 19),	/*!< verify: from --nodigest */
    QUERY_SIGNATURE	= (1 << 20),	/*!< verify: from --nosignature */
    QUERY_PATCHES	= (1 << 21),	/*!< verify: from --nopatches */
    QUERY_HDRCHK	= (1 << 22),	/*!< verify: from --nohdrchk */
    QUERY_FOR_LIST	= (1 << 23),	/*!< query:  from --list */
    QUERY_FOR_STATE	= (1 << 24),	/*!< query:  from --state */
    QUERY_FOR_DOCS	= (1 << 25),	/*!< query:  from --docfiles */
    QUERY_FOR_CONFIG	= (1 << 26),	/*!< query:  from --configfiles */
    QUERY_FOR_DUMPFILES	= (1 << 27),	/*!< query:  from --dump */
    QUERY_FOR_LICENSE	= (1 << 28),	/*!< query:  from --licensefiles */
    QUERY_FOR_ARTIFACT	= (1 << 29),	/*!< query:  from --artifacts */
};

typedef rpmFlags rpmQueryFlags;

#define	_QUERY_FOR_BITS	\
   (QUERY_FOR_LIST|QUERY_FOR_STATE|QUERY_FOR_DOCS|QUERY_FOR_CONFIG|\
    QUERY_FOR_LICENSE|QUERY_FOR_DUMPFILES)

/** \ingroup rpmcli
 * Bit(s) from common command line options.
 */
extern rpmQueryFlags rpmcliQueryFlags;

/** \ingroup rpmcli
 */
typedef struct rpmQVKArguments_s * QVA_t;

/** \ingroup rpmcli
 * Function to display iterator matches.
 *
 * @param qva		parsed query/verify options
 * @param ts		transaction set
 * @param h		header to use for query/verify
 * @return		0 on success
 */
typedef	int (*QVF_t) (QVA_t qva, rpmts ts, Header h);

/** \ingroup rpmcli
 * Function to query spec file.
 *
 * @param ts		transaction set
 * @param qva		parsed query/verify options
 * @param arg		query argument
 * @return		0 on success
 */
typedef	int (*QSpecF_t) (rpmts ts, QVA_t qva, const char * arg);

/** \ingroup rpmcli
 * Describe query/verify/signature command line operation.
 */
struct rpmQVKArguments_s {
    rpmQVSources qva_source;	/*!< Identify CLI arg type. */
    int 	qva_sourceCount;/*!< Exclusive option check (>1 is error). */
    rpmQueryFlags qva_flags;	/*!< Bit(s) to control operation. */
    rpmfileAttrs qva_fflags;	/*!< Bit(s) to filter on attribute. */

    QVF_t qva_showPackage;	/*!< Function to display iterator matches. */
    QSpecF_t qva_specQuery;	/*!< Function to query spec file. */
    char * qva_queryFormat;	/*!< Format for headerFormat(). */
    char	qva_mode;
		/*!<
		- 'q'	from --query, -q
		- 'Q'	from --querytags
		- 'V'	from --verify, -V
		- 'I'	from --import
		- 'K'	from --checksig, -K
		*/
};

/** \ingroup rpmcli
 */
extern struct rpmQVKArguments_s rpmQVKArgs;

/** \ingroup rpmcli
 */
extern struct poptOption rpmQVSourcePoptTable[];

/** \ingroup rpmcli
 */
extern struct poptOption rpmQueryPoptTable[];

/** \ingroup rpmcli
 */
extern struct poptOption rpmVerifyPoptTable[];

/** \ingroup rpmcli
 * Display list of tags that can be used in --queryformat.
 * @param fp	file handle to use for display
 */
void rpmDisplayQueryTags(FILE * fp);

/** \ingroup rpmcli
 * Display results of package query.
 * @todo Devise a meaningful return code.
 * @param qva		parsed query/verify options
 * @param ts		transaction set
 * @param h		header to use for query
 * @return		0 always
 */
int showQueryPackage(QVA_t qva, rpmts ts, Header h);

/** \ingroup rpmcli
 * Iterate over query/verify arg list.
 * @param ts		transaction set
 * @param qva		parsed query/verify options
 * @param argv		query argument(s) (or NULL)
 * @return		0 on success, else no. of failures
 */
int rpmcliArgIter(rpmts ts, QVA_t qva, ARGV_const_t argv);

/** \ingroup rpmcli
 * Display package information.
 * @todo hack: RPMQV_ALL can pass char ** arglist = NULL, not char * arg. Union?
 * @param ts		transaction set
 * @param qva		parsed query/verify options
 * @param argv		query argument(s) (or NULL)
 * @return		0 on success, else no. of failures
 */
int rpmcliQuery(rpmts ts, QVA_t qva, ARGV_const_t argv);

/** \ingroup rpmcli
 * Display results of package verify.
 * @param qva		parsed query/verify options
 * @param ts		transaction set
 * @param h		header to use for verify
 * @return		result of last non-zero verify return
 */
int showVerifyPackage(QVA_t qva, rpmts ts, Header h);

/**
 * Check package and header signatures.
 * @param qva		parsed query/verify options
 * @param ts		transaction set
 * @param fd		package file handle
 * @param fn		package file name
 * @return		0 on success, 1 on failure
 */
int rpmVerifySignatures(QVA_t qva, rpmts ts, FD_t fd, const char * fn);

/** \ingroup rpmcli
 * Verify package install.
 * @todo hack: RPMQV_ALL can pass char ** arglist = NULL, not char * arg. Union?
 * @param ts		transaction set
 * @param qva		parsed query/verify options
 * @param argv		verify argument(s) (or NULL)
 * @return		0 on success, else no. of failures
 */
int rpmcliVerify(rpmts ts, QVA_t qva, ARGV_const_t argv);

/* ==================================================================== */
/** \name RPMEIU */
/* --- install/upgrade/erase modes */

/** \ingroup rpmcli
 * Bit(s) to control rpmInstall() operation.
 */
enum rpmInstallFlags_e {
    INSTALL_NONE	= 0,
    INSTALL_PERCENT	= (1 << 0),	/*!< from --percent */
    INSTALL_HASH	= (1 << 1),	/*!< from --hash */
    INSTALL_NODEPS	= (1 << 2),	/*!< from --nodeps */
    INSTALL_NOORDER	= (1 << 3),	/*!< from --noorder */
    INSTALL_LABEL	= (1 << 4),	/*!< from --verbose (notify) */
    INSTALL_UPGRADE	= (1 << 5),	/*!< from --upgrade */
    INSTALL_FRESHEN	= (1 << 6),	/*!< from --freshen */
    INSTALL_INSTALL	= (1 << 7),	/*!< from --install */
    INSTALL_ERASE	= (1 << 8),	/*!< from --erase */
    INSTALL_ALLMATCHES	= (1 << 9),	/*!< from --allmatches */
    INSTALL_REINSTALL	= (1 << 10),	/*!< from --reinstall */
};

typedef rpmFlags rpmInstallFlags;

/** \ingroup rpmcli
 * Bit(s) to control rpmErase() operation.
 */
#define UNINSTALL_NONE INSTALL_NONE
#define UNINSTALL_NODEPS INSTALL_NODEPS
#define UNINSTALL_ALLMATCHES INSTALL_ALLMATCHES

/** \ingroup rpmcli
 * The rpm CLI generic transaction callback handler.
 * @todo Remove headerFormat() from the progress callback.
 * @deprecated Transaction callback arguments need to change, so don't rely on
 * this routine in the rpmcli API.
 *
 * @param arg		per-callback private data (e.g. an rpm header)
 * @param what		callback identifier
 * @param amount	per-callback progress info
 * @param total		per-callback progress info
 * @param key		opaque header key (e.g. file name or PyObject)
 * @param data		private data (e.g. rpmInstallInterfaceFlags)
 * @return		per-callback data (e.g. an opened FD_t)
 */
void * rpmShowProgress(const void * arg,
		const rpmCallbackType what,
		const rpm_loff_t amount,
		const rpm_loff_t total,
		fnpyKey key,
		void * data);

/** \ingroup rpmcli
 * Install source rpm package.
 * @param ts		transaction set
 * @param arg		source rpm file name
 * @retval *specFilePtr	(installed) spec file name
 * @retval *cookie
 * @return		0 on success
 */
int rpmInstallSource(rpmts ts, const char * arg,
		char ** specFilePtr,
		char ** cookie);


/** \ingroup rpmcli
 * Describe database command line requests.
 */
struct rpmInstallArguments_s {
    rpmtransFlags transFlags;
    rpmprobFilterFlags probFilter;
    rpmInstallFlags installInterfaceFlags;
    int numRelocations;
    int noDeps;
    int incldocs;
    rpmRelocation * relocations;
    char * prefix;
};

/** \ingroup rpmcli
 * Install/upgrade/freshen/reinstall binary rpm package.
 * @param ts		transaction set
 * @param ia		mode flags and parameters
 * @param fileArgv	array of package file names (NULL terminated)
 * @return		0 on success
 *
 * @todo		fileArgv is modified on errors, should be ARGV_const_t
 */
int rpmInstall(rpmts ts, struct rpmInstallArguments_s * ia, ARGV_t fileArgv);

/** \ingroup rpmcli
 * Erase binary rpm package.
 * @param ts		transaction set
 * @param ia		control args/bits
 * @param argv		array of package file names (NULL terminated)
 * @return		0 on success
 */

int rpmErase(rpmts ts, struct rpmInstallArguments_s * ia, ARGV_const_t argv);

/** \ingroup rpmcli
 */
extern struct rpmInstallArguments_s rpmIArgs;

/** \ingroup rpmcli
 */
extern struct poptOption rpmInstallPoptTable[];

/* ==================================================================== */
/** \name RPMK */

/** Import public key(s) to rpm keyring
 * @param ts		transaction set
 * @param argv		array of pubkey path arguments (NULL terminated)
 * @return		0 on success
 */
int rpmcliImportPubkeys(rpmts ts, ARGV_const_t argv);

/** \ingroup rpmcli
 * Verify package signatures
 * @param ts		transaction set
 * @param argv		array of package path arguments (NULL terminated)
 * @return		0 on success
 */
int rpmcliVerifySignatures(rpmts ts, ARGV_const_t argv);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMCLI */
