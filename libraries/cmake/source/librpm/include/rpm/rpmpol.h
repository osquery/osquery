#ifndef H_RPMPOL
#define H_RPMPOL

/** \ingroup rpmpol
 * \file lib/rpmpol.h
 * Structure(s) used for policy sets.
 */

#include <rpm/rpmtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

enum rpmpolFlags_e {
	RPMPOL_FLAG_NONE = 0,
	RPMPOL_FLAG_BASE = (1 << 0)
};

typedef rpmFlags rpmpolFlags;

#define RPMPOL_TYPE_DEFAULT "default"


#ifdef __cplusplus
}
#endif
#endif				/* H_rpmpol */
