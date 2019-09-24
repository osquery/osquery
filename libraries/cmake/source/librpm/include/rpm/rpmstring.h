#ifndef _RPMSTRING_H_
#define _RPMSTRING_H_

/** \ingroup rpmstring
 * \file rpmio/rpmstring.h
 * String manipulation helper functions
 */

#include <stddef.h>
#include <string.h>

#include <rpm/rpmutil.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmstring
 * Locale insensitive islower(3) 
 */
RPM_GNUC_CONST
static inline int rislower(int c)  {
    return (c >= 'a' && c <= 'z');
}

/** \ingroup rpmstring
 * Locale insensitive isupper(3)
 */
RPM_GNUC_CONST
static inline int risupper(int c)  {
    return (c >= 'A' && c <= 'Z');
}

/** \ingroup rpmstring
 * Locale insensitive isalpha(3)
 */
RPM_GNUC_CONST
static inline int risalpha(int c)  {
    return (rislower(c) || risupper(c));
}

/** \ingroup rpmstring
 * Locale insensitive isdigit(3)
 */
RPM_GNUC_CONST
static inline int risdigit(int c)  {
    return (c >= '0' && c <= '9');
}

/** \ingroup rpmstring
 * Locale insensitive isalnum(3)
 */
RPM_GNUC_CONST
static inline int risalnum(int c)  {
    return (risalpha(c) || risdigit(c));
}

/** \ingroup rpmstring
 * Locale insensitive isblank(3)
 */
RPM_GNUC_CONST
static inline int risblank(int c)  {
    return (c == ' ' || c == '\t');
}

/** \ingroup rpmstring
 * Locale insensitive isspace(3)
 */
RPM_GNUC_CONST
static inline int risspace(int c)  {
    return (risblank(c) || c == '\n' || c == '\r' || c == '\f' || c == '\v');
}

/** \ingroup rpmstring
 * Locale insensitive tolower(3)
 */
RPM_GNUC_CONST
static inline int rtolower(int c)  {
    return ((risupper(c)) ? (c | ('a' - 'A')) : c);
}

/** \ingroup rpmstring
 * Locale insensitive toupper(3)
 */
RPM_GNUC_CONST
static inline int rtoupper(int c)  {
    return ((rislower(c)) ? (c & ~('a' - 'A')) : c);
}

/**
 * Convert hex to binary nibble.
 * @param c            hex character
 * @return             binary nibble
 */
RPM_GNUC_CONST
static inline unsigned char rnibble(char c)
{
    if (c >= '0' && c <= '9')
	return (c - '0');
    if (c >= 'a' && c <= 'f')
	return (c - 'a') + 10;
    if (c >= 'A' && c <= 'F')
	return (c - 'A') + 10;
    return 0;
}

/**
 * Test for string equality
 * @param s1		string 1
 * @param s2		string 2
 * @return		0 if strings differ, 1 if equal
 */
static inline int rstreq(const char *s1, const char *s2)
{
    return (strcmp(s1, s2) == 0);
}

/**
 * Test for string equality
 * @param s1		string 1
 * @param s2		string 2
 * @param n		compare at most n characters
 * @return		0 if strings differ, 1 if equal
 */
static inline int rstreqn(const char *s1, const char *s2, size_t n)
{
    return (strncmp(s1, s2, n) == 0);
}

/** \ingroup rpmstring
 * Locale insensitive strcasecmp(3).
 */
RPM_GNUC_PURE
int rstrcasecmp(const char * s1, const char * s2)		;

/** \ingroup rpmstring
 * Locale insensitive strncasecmp(3).
 */
RPM_GNUC_PURE
int rstrncasecmp(const char *s1, const char * s2, size_t n)	;

/** \ingroup rpmstring
 * asprintf() clone
 */
int rasprintf(char **strp, const char *fmt, ...) RPM_GNUC_PRINTF(2, 3);

/** \ingroup rpmstring
 * Concatenate two strings with dynamically (re)allocated memory.
 * @param dest		pointer to destination string
 * @param src		source string
 * @return		realloc'd dest with src appended
 */
char *rstrcat(char **dest, const char *src);

/** \ingroup rpmstring
 * Concatenate multiple strings with dynamically (re)allocated memory.
 * @param dest		pointer to destination string
 * @param arg		NULL terminated list of strings to concatenate
 * @return		realloc'd dest with strings appended
 */
char *rstrscat(char **dest, const char *arg, ...) RPM_GNUC_NULL_TERMINATED;

/** \ingroup rpmstring
 * strlcpy() clone: 
 * Copy src to string dest of size n. At most n-1 characters
 * will be copied.  Always zero-terminates (unless n == 0).
 * Length of src is returned; if retval >= n, truncation occurred.
 * @param dest		destination buffer
 * @param src		string to copy
 * @param n		destination buffer size
 * @return		length of src string
 */
size_t rstrlcpy(char *dest, const char *src, size_t n);

/** \ingroup rpmstring
 * String hashing function
 * @param string	string to hash
 * @return		hash id
 */
RPM_GNUC_PURE
unsigned int rstrhash(const char * string);

#ifdef __cplusplus
}
#endif

#endif	/* _RPMSTRING_H_ */
