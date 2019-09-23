#ifndef _RPMSIGN_H
#define _RPMSIGN_H

/** \file sign/rpmsign.h
 *
 * Signature API
 */

#include <rpm/argv.h>
#include <rpm/rpmpgp.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rpmSignArgs {
    char *keyid;
    pgpHashAlgo hashalgo;
    int signfiles;
    /* ... what else? */
};

/** \ingroup rpmsign
 * Sign a package
 * @param path		path to package
 * @param args		signing parameters (or NULL for defaults)
 * @return		0 on success
 */
int rpmPkgSign(const char *path, const struct rpmSignArgs * args);

/** \ingroup rpmsign
 * Delete signature(s) from a package
 * @param path		path to package
 * @param args		signing parameters (or NULL for defaults)
 * @return		0 on success
 */
int rpmPkgDelSign(const char *path, const struct rpmSignArgs * args);

#ifdef __cplusplus
}
#endif

#endif /* _RPMSIGN_H */
