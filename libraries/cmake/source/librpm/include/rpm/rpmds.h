#ifndef H_RPMDS
#define H_RPMDS

/** \ingroup rpmdep rpmtrans
 * \file lib/rpmds.h
 * Structure(s) used for dependency tag sets.
 */

#include <time.h>

#include <rpm/rpmtypes.h>
#include <rpm/rpmps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 */
extern int _rpmds_nopromote;

/** \ingroup rpmds
 * Dependency Attributes.
 */
enum rpmsenseFlags_e {
    RPMSENSE_ANY	= 0,
    RPMSENSE_LESS	= (1 << 1),
    RPMSENSE_GREATER	= (1 << 2),
    RPMSENSE_EQUAL	= (1 << 3),
    /* bit 4 unused */
    RPMSENSE_POSTTRANS	= (1 << 5),	/*!< %posttrans dependency */
    RPMSENSE_PREREQ	= (1 << 6), 	/* legacy prereq dependency */
    RPMSENSE_PRETRANS	= (1 << 7),	/*!< Pre-transaction dependency. */
    RPMSENSE_INTERP	= (1 << 8),	/*!< Interpreter used by scriptlet. */
    RPMSENSE_SCRIPT_PRE	= (1 << 9),	/*!< %pre dependency. */
    RPMSENSE_SCRIPT_POST = (1 << 10),	/*!< %post dependency. */
    RPMSENSE_SCRIPT_PREUN = (1 << 11),	/*!< %preun dependency. */
    RPMSENSE_SCRIPT_POSTUN = (1 << 12), /*!< %postun dependency. */
    RPMSENSE_SCRIPT_VERIFY = (1 << 13),	/*!< %verify dependency. */
    RPMSENSE_FIND_REQUIRES = (1 << 14), /*!< find-requires generated dependency. */
    RPMSENSE_FIND_PROVIDES = (1 << 15), /*!< find-provides generated dependency. */

    RPMSENSE_TRIGGERIN	= (1 << 16),	/*!< %triggerin dependency. */
    RPMSENSE_TRIGGERUN	= (1 << 17),	/*!< %triggerun dependency. */
    RPMSENSE_TRIGGERPOSTUN = (1 << 18),	/*!< %triggerpostun dependency. */
    RPMSENSE_MISSINGOK	= (1 << 19),	/*!< suggests/enhances hint. */
    /* bits 20-23 unused */
    RPMSENSE_RPMLIB = (1 << 24),	/*!< rpmlib(feature) dependency. */
    RPMSENSE_TRIGGERPREIN = (1 << 25),	/*!< %triggerprein dependency. */
    RPMSENSE_KEYRING	= (1 << 26),
    /* bit 27 unused */
    RPMSENSE_CONFIG	= (1 << 28)
};

typedef rpmFlags rpmsenseFlags;

#define	RPMSENSE_SENSEMASK	15	 /* Mask to get senses, ie serial, */
                                         /* less, greater, equal.          */

#define	RPMSENSE_TRIGGER	\
	(RPMSENSE_TRIGGERPREIN | RPMSENSE_TRIGGERIN | RPMSENSE_TRIGGERUN | RPMSENSE_TRIGGERPOSTUN)

#define	_ALL_REQUIRES_MASK	(\
    RPMSENSE_INTERP | \
    RPMSENSE_SCRIPT_PRE | \
    RPMSENSE_SCRIPT_POST | \
    RPMSENSE_SCRIPT_PREUN | \
    RPMSENSE_SCRIPT_POSTUN | \
    RPMSENSE_SCRIPT_VERIFY | \
    RPMSENSE_FIND_REQUIRES | \
    RPMSENSE_RPMLIB | \
    RPMSENSE_KEYRING | \
    RPMSENSE_PRETRANS | \
    RPMSENSE_POSTTRANS | \
    RPMSENSE_PREREQ | \
    RPMSENSE_MISSINGOK)

#define	_notpre(_x)		((_x) & ~RPMSENSE_PREREQ)
#define	_INSTALL_ONLY_MASK \
    _notpre(RPMSENSE_SCRIPT_PRE|RPMSENSE_SCRIPT_POST|RPMSENSE_RPMLIB|RPMSENSE_KEYRING|RPMSENSE_PRETRANS|RPMSENSE_POSTTRANS)
#define	_ERASE_ONLY_MASK  \
    _notpre(RPMSENSE_SCRIPT_PREUN|RPMSENSE_SCRIPT_POSTUN)

#define	isLegacyPreReq(_x)  (((_x) & _ALL_REQUIRES_MASK) == RPMSENSE_PREREQ)
#define	isInstallPreReq(_x)	((_x) & _INSTALL_ONLY_MASK)
#define	isErasePreReq(_x)	((_x) & _ERASE_ONLY_MASK)



/** \ingroup rpmds
 * Return only those flags allowed for given type of dependencies
 * @param tagN		type of dependency
 * @param Flags		flags
 * @return		flags filtered to allowed bits
 */
rpmsenseFlags rpmSanitizeDSFlags(rpmTagVal tagN, rpmsenseFlags Flags);

/** \ingroup rpmds
 * Convert a string to the sense flags
 * @param str		the string
 * @param len		length of the string
 * @return		flags, zero for unknown relations
 */
rpmsenseFlags rpmParseDSFlags(const char *str, size_t len);

/** \ingroup rpmds
 * Reference a dependency set instance.
 * @param ds		dependency set
 * @return		new dependency set reference
 */
rpmds rpmdsLink(rpmds ds);

/** \ingroup rpmds
 * Destroy a dependency set.
 * @param ds		dependency set
 * @return		NULL always
 */
rpmds rpmdsFree(rpmds ds);

/** \ingroup rpmds
 * Create and load a dependency set.
 * @param h		header
 * @param tagN		type of dependency
 * @param flags		unused
 * @return		new dependency set
 */
rpmds rpmdsNew(Header h, rpmTagVal tagN, int flags);

/** \ingroup rpmds
 * Return new formatted dependency string.
 * @param dspfx		formatted dependency string prefix
 * @param ds		dependency set
 * @return		new formatted dependency (malloc'ed)
 */
char * rpmdsNewDNEVR(const char * dspfx, const rpmds ds);

/** \ingroup rpmds
 * Create, load and initialize a dependency for this header. 
 * @param h		header
 * @param tagN		type of dependency
 * @param Flags		comparison flags
 * @return		new dependency set
 */
rpmds rpmdsThis(Header h, rpmTagVal tagN, rpmsenseFlags Flags);

/** \ingroup rpmds
 * Create, load and initialize a dependency set of size 1.
 * @param tagN		type of dependency
 * @param N		name
 * @param EVR		epoch:version-release
 * @param Flags		comparison flags
 * @return		new dependency set
 */
rpmds rpmdsSingle(rpmTagVal tagN, const char * N, const char * EVR, rpmsenseFlags Flags);

/** \ingroup rpmds
 * Return a new dependency set of size 1 from the current iteration index
 * @param ds		dependency set
 * @return		new dependency set
 */
rpmds rpmdsCurrent(rpmds ds);

/** \ingroup rpmds
 * Write content of the dependency set to the header
 * @param ds		dependency set
 * @param h             header
 * @return		0 on success
 */
int rpmdsPutToHeader(rpmds ds, Header h);

/** \ingroup rpmds
 * Return dependency set count.
 * @param ds		dependency set
 * @return		current count
 */
int rpmdsCount(const rpmds ds);

/** \ingroup rpmds
 * Return dependency set index.
 * @param ds		dependency set
 * @return		current index
 */
int rpmdsIx(const rpmds ds);

/** \ingroup rpmds
 * Set dependency set index.
 * @param ds		dependency set
 * @param ix		new index
 * @return		current index
 */
int rpmdsSetIx(rpmds ds, int ix);

/** \ingroup rpmds
 * Return current formatted dependency string.
 * @param ds		dependency set
 * @return		current dependency DNEVR, NULL on invalid
 */
const char * rpmdsDNEVR(const rpmds ds);

/** \ingroup rpmds
 * Return one char indicating the type of the dependency.
 * @param ds		dependency set
 * @return		character
 */
char rpmdsD(const rpmds ds);

/** \ingroup rpmds
 * Return matching tagN for one char dependency type description.
 * @param deptype	character
 * @return		type of dependency
 */
rpmTagVal rpmdsDToTagN(char deptype);

/** \ingroup rpmds
 * Return current dependency name.
 * @param ds		dependency set
 * @return		current dependency name, NULL on invalid
 */
const char * rpmdsN(const rpmds ds);

/** \ingroup rpmds
 * Return current dependency epoch-version-release.
 * @param ds		dependency set
 * @return		current dependency EVR, NULL on invalid
 */
const char * rpmdsEVR(const rpmds ds);

/** \ingroup rpmds
 * Return current dependency triggerindex.
 * @param ds		dependency set
 * @return		current dependency trigger index, 0 on invalid
 */
int rpmdsTi(const rpmds ds);

/** \ingroup rpmds
 * Return current dependency flags.
 * @param ds		dependency set
 * @return		current dependency flags, 0 on invalid
 */
rpmsenseFlags rpmdsFlags(const rpmds ds);

/** \ingroup rpmds
 * Return current dependency type.
 * @param ds		dependency set
 * @return		current dependency type, 0 on invalid
 */
rpmTagVal rpmdsTagN(const rpmds ds);

/** \ingroup rpmds
 * Return current dependency type.
 * @param ds		dependency set
 * @return		current dependency type version tag, 0 on invalid
 */
rpmTagVal rpmdsTagEVR(const rpmds ds);

/** \ingroup rpmds
 * Return current dependency type.
 * @param ds		dependency set
 * @return		current dependency type flags tag, 0 on invalid
 */
rpmTagVal rpmdsTagF(const rpmds ds);

/** \ingroup rpmds
 * Return current dependency type.
 * @param ds		dependency set
 * @return		current dependency type trigger index tag, 0 on invalid
 */
rpmTagVal rpmdsTagTi(const rpmds ds);

/** \ingroup rpmds
 * Return dependency header instance, ie whether the dependency comes from 
 * an installed header or not.
 * @param ds		dependency set
 * @return		header instance of dependency (0 for not installed)
 */
unsigned int rpmdsInstance(rpmds ds);

/** \ingroup rpmds
 * Return current "Don't promote Epoch:" flag.
 *
 * This flag controls for Epoch: promotion when a dependency set is
 * compared. If the flag is set (for already installed packages), then
 * an unspecified value will be treated as Epoch: 0. Otherwise (for added
 * packages), the Epoch: portion of the comparison is skipped if the value
 * is not specified, i.e. an unspecified Epoch: is assumed to be equal
 * in dependency comparisons.
 *
 * @param ds		dependency set
 * @return		current "Don't promote Epoch:" flag
 */
int rpmdsNoPromote(const rpmds ds);

/** \ingroup rpmds
 * Set "Don't promote Epoch:" flag.
 * @param ds		dependency set
 * @param nopromote	Should an unspecified Epoch: be treated as Epoch: 0?
 * @return		previous "Don't promote Epoch:" flag
 */
int rpmdsSetNoPromote(rpmds ds, int nopromote);

/** \ingroup rpmds
 * Return current dependency color.
 * @param ds		dependency set
 * @return		current dependency color
 */
rpm_color_t rpmdsColor(const rpmds ds);

/** \ingroup rpmds
 * Return current dependency color.
 * @param ds		dependency set
 * @param color		new dependency color
 * @return		previous dependency color
 */
rpm_color_t rpmdsSetColor(const rpmds ds, rpm_color_t color);

/** \ingroup rpmds
 * Return next dependency set iterator index.
 * @param ds		dependency set
 * @return		dependency set iterator index, -1 on termination
 */
int rpmdsNext(rpmds ds);

/** \ingroup rpmds
 * Initialize dependency set iterator.
 * @param ds		dependency set
 * @return		dependency set
 */
rpmds rpmdsInit(rpmds ds);

/** \ingroup rpmds
 * Find a dependency set element using binary search.
 * @param ds		dependency set to search
 * @param ods		dependency set element to find.
 * @return		dependency index (or -1 if not found)
 */
int rpmdsFind(rpmds ds, const rpmds ods);

/** \ingroup rpmds
 * Merge a dependency set maintaining (N,EVR,Flags) sorted order.
 * @retval *dsp		(merged) dependency set
 * @param ods		dependency set to merge
 * @return		number of merged dependencies, -1 on error
 */
int rpmdsMerge(rpmds * dsp, rpmds ods);

/** \ingroup rpmds
 * Search a sorted dependency set for an element that overlaps.
 * A boolean result is saved (if allocated) and accessible through
 * rpmdsResult(ods) afterwards.
 * @param ds            dependency set to search
 * @param ods           dependency set element to find.
 * @return              dependency index (or -1 if not found)
 **/
int rpmdsSearch(rpmds ds, rpmds ods);

/** \ingroup rpmds
 * Compare two versioned dependency ranges, looking for overlap.
 * @param A		1st dependency
 * @param B		2nd dependency
 * @return		1 if dependencies overlap, 0 otherwise
 */
int rpmdsCompare(const rpmds A, const rpmds B);

/** \ingroup rpmds
 * Compare package provides dependencies from header with a single dependency.
 * @param h		header
 * @param req		dependency set
 * @param nopromote	Don't promote Epoch: in comparison?
 * @return		1 if any dependency overlaps, 0 otherwise
 */
int rpmdsAnyMatchesDep (const Header h, const rpmds req, int nopromote);

/** \ingroup rpmds
 * Compare package provides dependencies from header with a single dependency.
 * @param h		header
 * @param ix            index in header provides
 * @param req		dependency set
 * @param nopromote	Don't promote Epoch: in comparison?
 * @return		1 if any dependency overlaps, 0 otherwise
 */
int rpmdsMatchesDep (const Header h, int ix, const rpmds req, int nopromote);

/** \ingroup rpmds
 * Compare package name-version-release from header with a single dependency.
 * @param h		header
 * @param req		dependency set
 * @param nopromote	Don't promote Epoch: in comparison?
 * @return		1 if dependency overlaps, 0 otherwise
 */
int rpmdsNVRMatchesDep(const Header h, const rpmds req, int nopromote);

/**
 * Load rpmlib provides into a dependency set.
 * @retval *dsp		(loaded) dependency set
 * @param tblp		rpmlib provides table (NULL uses internal table)
 * @return		0 on success
 */
int rpmdsRpmlib(rpmds * dsp, const void * tblp);

/** \ingroup rpmds
 * Create and load a dependency set.
 * @param pool		shared string pool (or NULL for private pool)
 * @param h		header
 * @param tagN		type of dependency
 * @param flags		unused
 * @return		new dependency set
 */
rpmds rpmdsNewPool(rpmstrPool pool, Header h, rpmTagVal tagN, int flags);

/** \ingroup rpmds
 * Create, load and initialize a dependency for this header. 
 * @param pool		string pool (or NULL for private pool)
 * @param h		header
 * @param tagN		type of dependency
 * @param Flags		comparison flags
 * @return		new dependency set
 */
rpmds rpmdsThisPool(rpmstrPool pool,
		    Header h, rpmTagVal tagN, rpmsenseFlags Flags);

/** \ingroup rpmds
 * Create, load and initialize a dependency set of size 1.
 * @param pool		string pool (or NULL for private pool)
 * @param tagN		type of dependency
 * @param N		name
 * @param EVR		epoch:version-release
 * @param Flags		comparison flags
 * @return		new dependency set
 */
rpmds rpmdsSinglePool(rpmstrPool pool, rpmTagVal tagN,
		      const char * N, const char * EVR, rpmsenseFlags Flags);

/** \ingroup rpmds
 * Create, load and initialize a trigger dependency set of size 1.
 * @param pool		string pool (or NULL for private pool)
 * @param tagN		type of dependency
 * @param N		name
 * @param EVR		epoch:version-release
 * @param Flags		comparison flags
 * @param triggerIndex	trigger index
 * @return		new dependency set
 */
rpmds rpmdsSinglePoolTix(rpmstrPool pool, rpmTagVal tagN,
			    const char * N, const char * EVR, 
			    rpmsenseFlags Flags, int triggerIndex);

/**
 * Load rpmlib provides into a dependency set.
 * @param pool		shared string pool (or NULL for private pool)
 * @retval *dsp		(loaded) dependency set
 * @param tblp		rpmlib provides table (NULL uses internal table)
 * @return		0 on success
 */
int rpmdsRpmlibPool(rpmstrPool pool, rpmds * dsp, const void * tblp);


typedef enum rpmrichOp_e {
    RPMRICHOP_SINGLE  = 1,
    RPMRICHOP_AND     = 2,
    RPMRICHOP_OR      = 3,
    RPMRICHOP_IF      = 4,
    RPMRICHOP_ELSE    = 5,
    RPMRICHOP_WITH    = 6,
    RPMRICHOP_WITHOUT = 7,
    RPMRICHOP_UNLESS  = 8
} rpmrichOp;

typedef enum rpmrichParseType_e {
    RPMRICH_PARSE_SIMPLE = 1,	/* standard N <=> EVR dep */
    RPMRICH_PARSE_ENTER  = 2,	/* entering sub-dependency */
    RPMRICH_PARSE_LEAVE  = 3,	/* leaving sub-dependency */
    RPMRICH_PARSE_OP     = 4	/* parsed a rich dependency op */
} rpmrichParseType;

typedef rpmRC (*rpmrichParseFunction) (void *cbdata, rpmrichParseType type,
			 const char *n, int nl, const char *e, int el, rpmsenseFlags sense,
			 rpmrichOp op, char **emsg);

/**
 * Parse a rich dependency string
 * @param dstrp		pointer to sting, will be updated
 * @param emsg		returns the error string, can be NULL
 * @param cb		callback function
 * @param cbdata	callback function data
 * @return		RPMRC_OK on success
 */
rpmRC rpmrichParse(const char **dstrp, char **emsg, rpmrichParseFunction cb, void *cbdata);

/**
 * Parse a rich dependency string for a specific tag
 * @param dstrp		pointer to sting, will be updated
 * @param emsg		returns the error string, can be NULL
 * @param cb		callback function
 * @param cbdata	callback function data
 * @param tagN		type of dependency
 * @return		RPMRC_OK on success
 */
rpmRC rpmrichParseForTag(const char **dstrp, char **emsg, rpmrichParseFunction cb, void *cbdata, rpmTagVal tagN);


/**
 * Return if current depenency is rich
 * @param dep		the dependency
 * @return		1 is dependency is a rich 0 otherwise
 */
int rpmdsIsRich(rpmds dep);

/**
 * Return a string representation of the rich dependency op
 * @param op		the dependency op
 * @return		constant string, do not free
 */
const char *rpmrichOpStr(rpmrichOp op);

/**
 * Parse a rich dependency string
 * @param dep		the dependency
 * @param leftds	returns the left dependency
 * @param rightds	returns the right dependency
 * @param op		returns the rich dep op
 * @param emsg		returns the error string
 * @return		RPMRC_OK on success
 */
rpmRC rpmdsParseRichDep(rpmds dep, rpmds *leftds, rpmds *rightds, rpmrichOp *op, char **emsg);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMDS */
