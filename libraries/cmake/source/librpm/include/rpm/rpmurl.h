#ifndef H_RPMURL
#define H_RPMURL

/** \ingroup rpmio
 * \file rpmio/rpmurl.h
 *
 * A couple utils for URL Manipulation
 */

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmurl
 * Supported URL types.
 */
typedef enum urltype_e {
    URL_IS_UNKNOWN	= 0,	/*!< unknown (aka a file) */
    URL_IS_DASH		= 1,	/*!< stdin/stdout */
    URL_IS_PATH		= 2,	/*!< file://... */
    URL_IS_FTP		= 3,	/*!< ftp://... */
    URL_IS_HTTP		= 4,	/*!< http://... */
    URL_IS_HTTPS	= 5,	/*!< https://... */
    URL_IS_HKP		= 6	/*!< hkp://... */
} urltype;

/** \ingroup rpmurl
 * Return type of URL.
 * @param url		url string
 * @return		type of url
 */
urltype	urlIsURL(const char * url);

/** \ingroup rpmurl
 * Return path component of URL.
 * @param url		url string
 * @retval pathp	pointer to path component of url
 * @return		type of url
 */
urltype	urlPath(const char * url, const char ** pathp);

/** \ingroup rpmurl
 * Copy data from URL to local file.
 * @param url		url string of source
 * @param dest		file name of destination
 * @return		0 on success, -1 on error
 */
int urlGetFile(const char * url, const char * dest);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMURL */
