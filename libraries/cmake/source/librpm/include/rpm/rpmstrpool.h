#ifndef _RPMSTRPOOL_H
#define _RPMSTRPOOL_H

/** \ingroup rpmstrpool
 * \file rpmio/rpmstrpool.h
 *
 * String pools manipulation helper functions
 *
 */

#include <rpm/rpmtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmstrpool
 * Create a new, empty string pool.
 * @return		new string pool
 */
rpmstrPool rpmstrPoolCreate(void);

/** \ingroup rpmstrpool
 * Free a string pool and its contents. While other references exist,
 * this only decrements the reference count.
 * @param pool		string pool
 * @return		NULL always
 */
rpmstrPool rpmstrPoolFree(rpmstrPool pool);

/** \ingroup rpmstrpool
 * Reference a string pool
 * @param pool		string pool
 * @return		new string pool reference
 */
rpmstrPool rpmstrPoolLink(rpmstrPool pool);

/** \ingroup rpmstrpool
 * Freeze a string pool: new strings cannot be added to a frozen pool.
 * If keephash is 0, memory usage is minimized but string -> id lookups
 * are no longer possible and unfreezing is an expensive operation.
 * Id -> string lookups are always possible on a frozen pool too.
 * @param pool		string pool
 * @param keephash	should string -> id hash be kept around?
 */
void rpmstrPoolFreeze(rpmstrPool pool, int keephash);

/** \ingroup rpmstrpool
 * Unfreeze a string pool to allow new additions again.
 * If keephash was not specified on freezing, this requires rehashing
 * the entire pool contents.
 * @param pool		string pool
 */
void rpmstrPoolUnfreeze(rpmstrPool pool);

/** \ingroup rpmstrpool
 * Look up the id of a string. If create is specified the string is
 * added to the pool if it does not already exist. Creation can only
 * fail if the pool is in frozen state.
 * @param pool		string pool
 * @param s		\0-terminated string to look up
 * @param create	should an id be created if not already present?
 * @return		id of the string or 0 for not found
 */
rpmsid rpmstrPoolId(rpmstrPool pool, const char *s, int create);

/** \ingroup rpmstrpool
 * Look up the id of a string with predetermined length. The string does
 * not have to be \0-terminated. If create is specified the string is
 * added to the pool if it does not already exist. Creation can only
 * fail if the pool is in frozen state. 
 * @param pool		string pool
 * @param s		string to look up
 * @param slen		number of characters from s to consider
 * @param create	should an id be created if not already present?
 * @return		id of the string or 0 for not found
 */
rpmsid rpmstrPoolIdn(rpmstrPool pool, const char *s, size_t slen, int create);

/** \ingroup rpmstrpool
 * Look up a string by its pool id.
 * @param pool		string pool
 * @param sid		pool id of a string
 * @return		pointer to the string or NULL for invalid id
 */
const char * rpmstrPoolStr(rpmstrPool pool, rpmsid sid);

/** \ingroup rpmstrpool
 * Return length of a string by its pool id. The result is equal to
 * calling strlen() on a string retrieved through rpmstrPoolStr(), but
 * the pool might be able to optimize the calculation.
 * @param pool		string pool
 * @param sid		pool id of a string
 * @return		length of the string, 0 for invalid pool or id
 */
size_t rpmstrPoolStrlen(rpmstrPool pool, rpmsid sid);

/** \ingroup rpmstrpool
 * Compare two strings for equality by their ids. The result is equal to
 * calling rstreq() on two strings retrieved through rpmstrPoolStr() but
 * when the id's are within the same pool, this runs in constant time.
 * @param poolA		string pool of the first string
 * @param sidA		pool id of the first string
 * @param poolB		string pool of the second string
 * @param sidB		pool id of the second string
 * @return		1 if strings are equal, 0 otherwise
 */
int rpmstrPoolStreq(rpmstrPool poolA, rpmsid sidA,
                    rpmstrPool poolB, rpmsid sidB);

/** \ingroup rpmstrpool
 * Return the number of strings stored in the pool. This number is
 * also the highest legal id for the pool.
 * @param pool		string pool
 * @return		number of strings in the pool
 */
rpmsid rpmstrPoolNumStr(rpmstrPool pool);

#ifdef __cplusplus
}
#endif

#endif /* _RPMSIDPOOL_H */
