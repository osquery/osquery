#ifndef H_RPMLOG
#define H_RPMLOG 1

/** \ingroup rpmio
 * \file rpmio/rpmlog.h
 * Yet Another syslog(3) API clone.
 * Used to unify rpmError() and rpmMessage() interfaces in rpm.
 */

#include <stdarg.h>
#include <stdio.h>

#include <rpm/rpmutil.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmlog
 * RPM Log levels.
 * priorities/facilities are encoded into a single 32-bit quantity, where the
 * bottom 3 bits are the priority (0-7) and the top 28 bits are the facility
 * (0-big number).  Both the priorities and the facilities map roughly
 * one-to-one to strings in the syslogd(8) source code.  This mapping is
 * included in this file.
 *
 * priorities (these are ordered)
 */
typedef enum rpmlogLvl_e {
    RPMLOG_EMERG	= 0,	/*!< system is unusable */
    RPMLOG_ALERT	= 1,	/*!< action must be taken immediately */
    RPMLOG_CRIT		= 2,	/*!< critical conditions */
    RPMLOG_ERR		= 3,	/*!< error conditions */
    RPMLOG_WARNING	= 4,	/*!< warning conditions */
    RPMLOG_NOTICE	= 5,	/*!< normal but significant condition */
    RPMLOG_INFO		= 6,	/*!< informational */
    RPMLOG_DEBUG	= 7	/*!< debug-level messages */
} rpmlogLvl;

#define	RPMLOG_PRIMASK	0x07	/* mask to extract priority part (internal) */
				/* extract priority */
#define	RPMLOG_PRI(p)	((p) & RPMLOG_PRIMASK)
#define	RPMLOG_MAKEPRI(fac, pri)	((((unsigned)(fac)) << 3) | (pri))

/** \ingroup rpmlog
 * facility codes
 */
typedef	enum rpmlogFac_e {
    RPMLOG_KERN		= (0<<3),	/*!< kernel messages */
    RPMLOG_USER		= (1<<3),	/*!< random user-level messages */
    RPMLOG_MAIL		= (2<<3),	/*!< mail system */
    RPMLOG_DAEMON	= (3<<3),	/*!< system daemons */
    RPMLOG_AUTH		= (4<<3),	/*!< security/authorization messages */
    RPMLOG_SYSLOG	= (5<<3),	/*!< messages generated internally by syslogd */
    RPMLOG_LPR		= (6<<3),	/*!< line printer subsystem */
    RPMLOG_NEWS		= (7<<3),	/*!< network news subsystem */
    RPMLOG_UUCP		= (8<<3),	/*!< UUCP subsystem */
    RPMLOG_CRON		= (9<<3),	/*!< clock daemon */
    RPMLOG_AUTHPRIV	= (10<<3),	/*!< security/authorization messages (private) */
    RPMLOG_FTP		= (11<<3),	/*!< ftp daemon */

	/* other codes through 15 reserved for system use */
    RPMLOG_LOCAL0	= (16<<3),	/*!< reserved for local use */
    RPMLOG_LOCAL1	= (17<<3),	/*!< reserved for local use */
    RPMLOG_LOCAL2	= (18<<3),	/*!< reserved for local use */
    RPMLOG_LOCAL3	= (19<<3),	/*!< reserved for local use */
    RPMLOG_LOCAL4	= (20<<3),	/*!< reserved for local use */
    RPMLOG_LOCAL5	= (21<<3),	/*!< reserved for local use */
    RPMLOG_LOCAL6	= (22<<3),	/*!< reserved for local use */
    RPMLOG_LOCAL7	= (23<<3),	/*!< reserved for local use */

#define	RPMLOG_NFACILITIES 24	/*!< current number of facilities */
    RPMLOG_ERRMSG	= (((unsigned)(RPMLOG_NFACILITIES+0))<<3)
} rpmlogFac;

#define	RPMLOG_FACMASK	0x03f8	/*!< mask to extract facility part */
#define	RPMLOG_FAC(p)	(((p) & RPMLOG_FACMASK) >> 3)


/*
 * arguments to setlogmask.
 */
#define	RPMLOG_MASK(pri) (1 << ((unsigned)(pri)))	/*!< mask for one priority */
#define	RPMLOG_UPTO(pri) ((1 << (((unsigned)(pri))+1)) - 1)	/*!< all priorities through pri */

/*
 * Option flags for openlog.
 *
 * RPMLOG_ODELAY no longer does anything.
 * RPMLOG_NDELAY is the inverse of what it used to be.
 */
#define	RPMLOG_PID	0x01	/*!< log the pid with each message */
#define	RPMLOG_CONS	0x02	/*!< log on the console if errors in sending */
#define	RPMLOG_ODELAY	0x04	/*!< delay open until first syslog() (default) */
#define	RPMLOG_NDELAY	0x08	/*!< don't delay open */
#define	RPMLOG_NOWAIT	0x10	/*!< don't wait for console forks: DEPRECATED */
#define	RPMLOG_PERROR	0x20	/*!< log to stderr as well */

/* \ingroup rpmlog
 * Option flags for callback return value.
 */
#define RPMLOG_DEFAULT	0x01	/*!< perform default logging */	
#define RPMLOG_EXIT	0x02	/*!< exit after logging */

/** \ingroup rpmlog
 */
typedef struct rpmlogRec_s * rpmlogRec;

/** \ingroup rpmlog
 * Retrieve log message string from rpmlog record
 * @param rec		rpmlog record
 * @return		log message
 */
const char * rpmlogRecMessage(rpmlogRec rec);

/** \ingroup rpmlog
 * Retrieve log priority from rpmlog record
 * @param rec		rpmlog record
 * @return		log priority
 */
rpmlogLvl rpmlogRecPriority(rpmlogRec rec);

typedef void * rpmlogCallbackData;

/** \ingroup rpmlog
  * @param rec		rpmlog record
  * @param data		private callback data
  * @return		flags to define further behavior:
  * 			RPMLOG_DEFAULT to perform default logging,
  * 			RPMLOG_EXIT to exit after processing, 
  * 			0 to return after callback
  */
typedef int (*rpmlogCallback) (rpmlogRec rec, rpmlogCallbackData data);

/** \ingroup rpmlog
 * Return number of rpmError() ressages.
 * @return		number of messages
 */
int rpmlogGetNrecs(void)	;

/** \ingroup rpmlog
 * Print all rpmError() messages.
 * @param f		file handle (NULL uses stderr)
 */
void rpmlogPrint(FILE *f);

/** \ingroup rpmlog
 * Close desriptor used to write to system logger.
 * @todo Implement.
 */
void rpmlogClose (void);

/** \ingroup rpmlog
 * Open connection to system logger.
 * @todo Implement.
 */
void rpmlogOpen (const char * ident, int option, int facility);

/** \ingroup rpmlog
 * Set the log mask level.
 * @param mask		log mask (0 is no operation)
 * @return		previous log mask
 */
int rpmlogSetMask (int mask);

/** \ingroup rpmlog
 * Generate a log message using FMT string and option arguments.
 */
void rpmlog (int code, const char *fmt, ...) RPM_GNUC_PRINTF(2, 3);

/** \ingroup rpmlog
 * Return text of last rpmError() message.
 * @return		text of last message
 */
const char * rpmlogMessage(void);

/** \ingroup rpmlog
 * Return error code from last rpmError() message.
 * @deprecated Perl-RPM needs, what's really needed is predictable, non-i18n
 *	encumbered, error text that can be retrieved through rpmlogMessage()
 *	and parsed IMHO.
 * @return		code from last message
 */
int rpmlogCode(void);

/** \ingroup rpmlog
 * Return translated prefix string (if any) given log level.
 * @param pri		log priority
 * @return		message prefix (or "" for none)
 */
const char * rpmlogLevelPrefix(rpmlogLvl pri);

/** \ingroup rpmlog
 * Set rpmlog callback function.
 * @param cb		rpmlog callback function
 * @param data		callback private (user) data
 * @return		previous rpmlog callback function
 */
rpmlogCallback rpmlogSetCallback(rpmlogCallback cb, rpmlogCallbackData data);

/** \ingroup rpmlog
 * Set rpmlog file handle.
 * @param fp		rpmlog file handle (NULL uses stdout/stderr)
 * @return		previous rpmlog file handle
 */
FILE * rpmlogSetFile(FILE * fp);

#define	rpmSetVerbosity(_lvl)	\
	((void)rpmlogSetMask( RPMLOG_UPTO( RPMLOG_PRI(_lvl))))
#define	rpmIncreaseVerbosity()	\
    ((void)rpmlogSetMask(((((unsigned)(rpmlogSetMask(0) & 0xff)) << 1) | 1)))
#define	rpmDecreaseVerbosity()	\
	((void)rpmlogSetMask((((int)(rpmlogSetMask(0) & 0xff)) >> 1)))
#define	rpmIsNormal()		\
	(rpmlogSetMask(0) >= RPMLOG_MASK( RPMLOG_NOTICE ))
#define	rpmIsVerbose()		\
	(rpmlogSetMask(0) >= RPMLOG_MASK( RPMLOG_INFO ))
#define	rpmIsDebug()		\
	(rpmlogSetMask(0) >= RPMLOG_MASK( RPMLOG_DEBUG ))

#ifdef __cplusplus
}
#endif

#endif /* H_RPMLOG */
