#ifndef	H_RPMIO
#define	H_RPMIO

/** \ingroup rpmio
 * \file rpmio/rpmio.h
 *
 * RPM I/O API (Fd_t is RPM equivalent to libc's FILE)
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rpm/rpmtypes.h>
#include <rpm/rpmsw.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmio
 */
typedef const struct FDIO_s * FDIO_t;


/** \ingroup rpmio
 * \name RPMIO Interface.
 */

/** \ingroup rpmio
 * strerror(3) clone.
 */
const char * Fstrerror(FD_t fd);

/** \ingroup rpmio
 * fread(3) clone.
 */
ssize_t Fread(void * buf, size_t size, size_t nmemb, FD_t fd);

/** \ingroup rpmio
 * fwrite(3) clone.
 */
ssize_t Fwrite(const void * buf, size_t size, size_t nmemb, FD_t fd);

/** \ingroup rpmio
 * fseek(3) clone.
 */
int Fseek(FD_t fd, off_t offset, int whence);

/** \ingroup rpmio
 * ftell(3) clone.
 */
off_t Ftell(FD_t fd);

/** \ingroup rpmio
 * fclose(3) clone.
 */
int Fclose( FD_t fd);

/** \ingroup rpmio
 */
FD_t	Fdopen(FD_t ofd, const char * fmode);

/** \ingroup rpmio
 * fopen(3) clone.
 */
FD_t	Fopen(const char * path,
			const char * fmode);


/** \ingroup rpmio
 * fflush(3) clone.
 */
int Fflush(FD_t fd);

/** \ingroup rpmio
 * ferror(3) clone.
 */
int Ferror(FD_t fd);

/** \ingroup rpmio
 * fileno(3) clone.
 */
int Fileno(FD_t fd);

/** \ingroup rpmio
 * fcntl(2) clone.
 */
int Fcntl(FD_t fd, int op, void *lip);

/** \ingroup rpmio
 * Get informative description (eg file name) from fd for diagnostic output.
 */
const char * Fdescr(FD_t fd);

/** \ingroup rpmio
 * \name RPMIO Utilities.
 */

/** \ingroup rpmio
 */
off_t	fdSize(FD_t fd);

/** \ingroup rpmio
 */
FD_t fdDup(int fdno);

/** \ingroup rpmio
 */
FD_t fdLink(FD_t fd);

/** \ingroup rpmio
 */
FD_t fdFree(FD_t fd);

/**
 */
off_t ufdCopy(FD_t sfd, FD_t tfd);

/** \ingroup rpmio
 * Identify per-desciptor I/O operation statistics.
 */
typedef enum fdOpX_e {
    FDSTAT_READ		= 0,	/*!< Read statistics index. */
    FDSTAT_WRITE	= 1,	/*!< Write statistics index. */
    FDSTAT_SEEK		= 2,	/*!< Seek statistics index. */
    FDSTAT_CLOSE	= 3,	/*!< Close statistics index */
    FDSTAT_DIGEST	= 4,	/*!< Digest statistics index. */
    FDSTAT_MAX		= 5
} fdOpX;

/** \ingroup rpmio
 *
 */
rpmop fdOp(FD_t fd, fdOpX opx);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMIO */
