/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Darwin ACL support */
#define ARCHIVE_ACL_DARWIN 1

/* FreeBSD ACL support */
/* #undef ARCHIVE_ACL_FREEBSD */

/* FreeBSD NFSv4 ACL support */
/* #undef ARCHIVE_ACL_FREEBSD_NFS4 */

/* Linux POSIX.1e ACL support via libacl */
/* #undef ARCHIVE_ACL_LIBACL */

/* Linux NFSv4 ACL support via librichacl */
/* #undef ARCHIVE_ACL_LIBRICHACL */

/* Solaris ACL support */
/* #undef ARCHIVE_ACL_SUNOS */

/* Solaris NFSv4 ACL support */
/* #undef ARCHIVE_ACL_SUNOS_NFS4 */

/* MD5 via ARCHIVE_CRYPTO_MD5_LIBC supported. */
/* #undef ARCHIVE_CRYPTO_MD5_LIBC */

/* MD5 via ARCHIVE_CRYPTO_MD5_LIBMD supported. */
/* #undef ARCHIVE_CRYPTO_MD5_LIBMD */

/* MD5 via ARCHIVE_CRYPTO_MD5_LIBSYSTEM supported. */
#define ARCHIVE_CRYPTO_MD5_LIBSYSTEM 1

/* MD5 via ARCHIVE_CRYPTO_MD5_NETTLE supported. */
/* #undef ARCHIVE_CRYPTO_MD5_NETTLE */

/* MD5 via ARCHIVE_CRYPTO_MD5_OPENSSL supported. */
#define ARCHIVE_CRYPTO_MD5_OPENSSL 1

/* MD5 via ARCHIVE_CRYPTO_MD5_WIN supported. */
/* #undef ARCHIVE_CRYPTO_MD5_WIN */

/* RMD160 via ARCHIVE_CRYPTO_RMD160_LIBC supported. */
/* #undef ARCHIVE_CRYPTO_RMD160_LIBC */

/* RMD160 via ARCHIVE_CRYPTO_RMD160_LIBMD supported. */
/* #undef ARCHIVE_CRYPTO_RMD160_LIBMD */

/* RMD160 via ARCHIVE_CRYPTO_RMD160_NETTLE supported. */
/* #undef ARCHIVE_CRYPTO_RMD160_NETTLE */

/* RMD160 via ARCHIVE_CRYPTO_RMD160_OPENSSL supported. */
#define ARCHIVE_CRYPTO_RMD160_OPENSSL 1

/* SHA1 via ARCHIVE_CRYPTO_SHA1_LIBC supported. */
/* #undef ARCHIVE_CRYPTO_SHA1_LIBC */

/* SHA1 via ARCHIVE_CRYPTO_SHA1_LIBMD supported. */
/* #undef ARCHIVE_CRYPTO_SHA1_LIBMD */

/* SHA1 via ARCHIVE_CRYPTO_SHA1_LIBSYSTEM supported. */
#define ARCHIVE_CRYPTO_SHA1_LIBSYSTEM 1

/* SHA1 via ARCHIVE_CRYPTO_SHA1_NETTLE supported. */
/* #undef ARCHIVE_CRYPTO_SHA1_NETTLE */

/* SHA1 via ARCHIVE_CRYPTO_SHA1_OPENSSL supported. */
#define ARCHIVE_CRYPTO_SHA1_OPENSSL 1

/* SHA1 via ARCHIVE_CRYPTO_SHA1_WIN supported. */
/* #undef ARCHIVE_CRYPTO_SHA1_WIN */

/* SHA256 via ARCHIVE_CRYPTO_SHA256_LIBC supported. */
/* #undef ARCHIVE_CRYPTO_SHA256_LIBC */

/* SHA256 via ARCHIVE_CRYPTO_SHA256_LIBC2 supported. */
/* #undef ARCHIVE_CRYPTO_SHA256_LIBC2 */

/* SHA256 via ARCHIVE_CRYPTO_SHA256_LIBC3 supported. */
/* #undef ARCHIVE_CRYPTO_SHA256_LIBC3 */

/* SHA256 via ARCHIVE_CRYPTO_SHA256_LIBMD supported. */
/* #undef ARCHIVE_CRYPTO_SHA256_LIBMD */

/* SHA256 via ARCHIVE_CRYPTO_SHA256_LIBSYSTEM supported. */
#define ARCHIVE_CRYPTO_SHA256_LIBSYSTEM 1

/* SHA256 via ARCHIVE_CRYPTO_SHA256_NETTLE supported. */
/* #undef ARCHIVE_CRYPTO_SHA256_NETTLE */

/* SHA256 via ARCHIVE_CRYPTO_SHA256_OPENSSL supported. */
#define ARCHIVE_CRYPTO_SHA256_OPENSSL 1

/* SHA256 via ARCHIVE_CRYPTO_SHA256_WIN supported. */
/* #undef ARCHIVE_CRYPTO_SHA256_WIN */

/* SHA384 via ARCHIVE_CRYPTO_SHA384_LIBC supported. */
/* #undef ARCHIVE_CRYPTO_SHA384_LIBC */

/* SHA384 via ARCHIVE_CRYPTO_SHA384_LIBC2 supported. */
/* #undef ARCHIVE_CRYPTO_SHA384_LIBC2 */

/* SHA384 via ARCHIVE_CRYPTO_SHA384_LIBC3 supported. */
/* #undef ARCHIVE_CRYPTO_SHA384_LIBC3 */

/* SHA384 via ARCHIVE_CRYPTO_SHA384_LIBSYSTEM supported. */
#define ARCHIVE_CRYPTO_SHA384_LIBSYSTEM 1

/* SHA384 via ARCHIVE_CRYPTO_SHA384_NETTLE supported. */
/* #undef ARCHIVE_CRYPTO_SHA384_NETTLE */

/* SHA384 via ARCHIVE_CRYPTO_SHA384_OPENSSL supported. */
#define ARCHIVE_CRYPTO_SHA384_OPENSSL 1

/* SHA384 via ARCHIVE_CRYPTO_SHA384_WIN supported. */
/* #undef ARCHIVE_CRYPTO_SHA384_WIN */

/* SHA512 via ARCHIVE_CRYPTO_SHA512_LIBC supported. */
/* #undef ARCHIVE_CRYPTO_SHA512_LIBC */

/* SHA512 via ARCHIVE_CRYPTO_SHA512_LIBC2 supported. */
/* #undef ARCHIVE_CRYPTO_SHA512_LIBC2 */

/* SHA512 via ARCHIVE_CRYPTO_SHA512_LIBC3 supported. */
/* #undef ARCHIVE_CRYPTO_SHA512_LIBC3 */

/* SHA512 via ARCHIVE_CRYPTO_SHA512_LIBMD supported. */
/* #undef ARCHIVE_CRYPTO_SHA512_LIBMD */

/* SHA512 via ARCHIVE_CRYPTO_SHA512_LIBSYSTEM supported. */
#define ARCHIVE_CRYPTO_SHA512_LIBSYSTEM 1

/* SHA512 via ARCHIVE_CRYPTO_SHA512_NETTLE supported. */
/* #undef ARCHIVE_CRYPTO_SHA512_NETTLE */

/* SHA512 via ARCHIVE_CRYPTO_SHA512_OPENSSL supported. */
#define ARCHIVE_CRYPTO_SHA512_OPENSSL 1

/* SHA512 via ARCHIVE_CRYPTO_SHA512_WIN supported. */
/* #undef ARCHIVE_CRYPTO_SHA512_WIN */

/* AIX xattr support */
/* #undef ARCHIVE_XATTR_AIX */

/* Darwin xattr support */
#define ARCHIVE_XATTR_DARWIN 1

/* FreeBSD xattr support */
/* #undef ARCHIVE_XATTR_FREEBSD */

/* Linux xattr support */
/* #undef ARCHIVE_XATTR_LINUX */

/* Version number of bsdcat */
#define BSDCAT_VERSION_STRING "3.3.2"

/* Version number of bsdcpio */
#define BSDCPIO_VERSION_STRING "3.3.2"

/* Version number of bsdtar */
#define BSDTAR_VERSION_STRING "3.3.2"

/* Define to 1 if the system has the type `ace_t'. */
/* #undef HAVE_ACE_T */

/* Define to 1 if you have the `acl' function. */
/* #undef HAVE_ACL */

/* Define to 1 if the system has the type `aclent_t'. */
/* #undef HAVE_ACLENT_T */

/* Define to 1 if you have the `acl_add_flag_np' function. */
#define HAVE_ACL_ADD_FLAG_NP 1

/* Define to 1 if you have the `acl_add_perm' function. */
#define HAVE_ACL_ADD_PERM 1

/* Define to 1 if you have the `acl_clear_flags_np' function. */
#define HAVE_ACL_CLEAR_FLAGS_NP 1

/* Define to 1 if you have the `acl_clear_perms' function. */
#define HAVE_ACL_CLEAR_PERMS 1

/* Define to 1 if you have the `acl_create_entry' function. */
#define HAVE_ACL_CREATE_ENTRY 1

/* Define to 1 if you have the `acl_delete_def_file' function. */
#define HAVE_ACL_DELETE_DEF_FILE 1

/* Define to 1 if the system has the type `acl_entry_t'. */
#define HAVE_ACL_ENTRY_T 1

/* Define to 1 if you have the `acl_free' function. */
#define HAVE_ACL_FREE 1

/* Define to 1 if you have the `acl_get_brand_np' function. */
/* #undef HAVE_ACL_GET_BRAND_NP */

/* Define to 1 if you have the `acl_get_entry' function. */
#define HAVE_ACL_GET_ENTRY 1

/* Define to 1 if you have the `acl_get_entry_type_np' function. */
/* #undef HAVE_ACL_GET_ENTRY_TYPE_NP */

/* Define to 1 if you have the `acl_get_fd' function. */
#define HAVE_ACL_GET_FD 1

/* Define to 1 if you have the `acl_get_fd_np' function. */
#define HAVE_ACL_GET_FD_NP 1

/* Define to 1 if you have the `acl_get_file' function. */
#define HAVE_ACL_GET_FILE 1

/* Define to 1 if you have the `acl_get_flagset_np' function. */
#define HAVE_ACL_GET_FLAGSET_NP 1

/* Define to 1 if you have the `acl_get_flag_np' function. */
#define HAVE_ACL_GET_FLAG_NP 1

/* Define to 1 if you have the `acl_get_link_np' function. */
#define HAVE_ACL_GET_LINK_NP 1

/* Define to 1 if you have the `acl_get_perm' function. */
/* #undef HAVE_ACL_GET_PERM */

/* Define to 1 if you have the `acl_get_permset' function. */
#define HAVE_ACL_GET_PERMSET 1

/* Define to 1 if you have the `acl_get_perm_np' function. */
#define HAVE_ACL_GET_PERM_NP 1

/* Define to 1 if you have the `acl_get_qualifier' function. */
#define HAVE_ACL_GET_QUALIFIER 1

/* Define to 1 if you have the `acl_get_tag_type' function. */
#define HAVE_ACL_GET_TAG_TYPE 1

/* Define to 1 if you have the `acl_init' function. */
#define HAVE_ACL_INIT 1

/* Define to 1 if you have the `acl_is_trivial_np' function. */
/* #undef HAVE_ACL_IS_TRIVIAL_NP */

/* Define to 1 if you have the <acl/libacl.h> header file. */
/* #undef HAVE_ACL_LIBACL_H */

/* Define to 1 if the system has the type `acl_permset_t'. */
#define HAVE_ACL_PERMSET_T 1

/* Define to 1 if you have the `acl_set_entry_type_np' function. */
/* #undef HAVE_ACL_SET_ENTRY_TYPE_NP */

/* Define to 1 if you have the `acl_set_fd' function. */
#define HAVE_ACL_SET_FD 1

/* Define to 1 if you have the `acl_set_fd_np' function. */
#define HAVE_ACL_SET_FD_NP 1

/* Define to 1 if you have the `acl_set_file' function. */
#define HAVE_ACL_SET_FILE 1

/* Define to 1 if you have the `acl_set_link_np' function. */
#define HAVE_ACL_SET_LINK_NP 1

/* Define to 1 if you have the `acl_set_qualifier' function. */
#define HAVE_ACL_SET_QUALIFIER 1

/* Define to 1 if you have the `acl_set_tag_type' function. */
#define HAVE_ACL_SET_TAG_TYPE 1

/* Define to 1 if the system has the type `acl_t'. */
#define HAVE_ACL_T 1

/* Define to 1 if the system has the type `acl_tag_t'. */
#define HAVE_ACL_TAG_T 1

/* Define to 1 if you have the `arc4random_buf' function. */
#define HAVE_ARC4RANDOM_BUF 1

/* Define to 1 if you have the <attr/xattr.h> header file. */
/* #undef HAVE_ATTR_XATTR_H */

/* Define to 1 if you have the <bcrypt.h> header file. */
/* #undef HAVE_BCRYPT_H */

/* Define to 1 if you have the <bzlib.h> header file. */
#define HAVE_BZLIB_H 1

/* Define to 1 if you have the `chflags' function. */
#define HAVE_CHFLAGS 1

/* Define to 1 if you have the `chown' function. */
#define HAVE_CHOWN 1

/* Define to 1 if you have the `chroot' function. */
#define HAVE_CHROOT 1

/* Define to 1 if you have the <copyfile.h> header file. */
#define HAVE_COPYFILE_H 1

/* Define to 1 if you have the `ctime_r' function. */
#define HAVE_CTIME_R 1

/* Define to 1 if you have the <ctype.h> header file. */
#define HAVE_CTYPE_H 1

/* Define to 1 if you have the `cygwin_conv_path' function. */
/* #undef HAVE_CYGWIN_CONV_PATH */

/* Define to 1 if you have the declaration of `ACE_GETACL', and to 0 if you
   don't. */
/* #undef HAVE_DECL_ACE_GETACL */

/* Define to 1 if you have the declaration of `ACE_GETACLCNT', and to 0 if you
   don't. */
/* #undef HAVE_DECL_ACE_GETACLCNT */

/* Define to 1 if you have the declaration of `ACE_SETACL', and to 0 if you
   don't. */
/* #undef HAVE_DECL_ACE_SETACL */

/* Define to 1 if you have the declaration of `ACL_SYNCHRONIZE', and to 0 if
   you don't. */
#define HAVE_DECL_ACL_SYNCHRONIZE 1

/* Define to 1 if you have the declaration of `ACL_TYPE_EXTENDED', and to 0 if
   you don't. */
#define HAVE_DECL_ACL_TYPE_EXTENDED 1

/* Define to 1 if you have the declaration of `ACL_TYPE_NFS4', and to 0 if you
   don't. */
#define HAVE_DECL_ACL_TYPE_NFS4 0

/* Define to 1 if you have the declaration of `ACL_USER', and to 0 if you
   don't. */
#define HAVE_DECL_ACL_USER 0

/* Define to 1 if you have the declaration of `EXTATTR_NAMESPACE_USER', and to
   0 if you don't. */
#define HAVE_DECL_EXTATTR_NAMESPACE_USER 0

/* Define to 1 if you have the declaration of `GETACL', and to 0 if you don't.
   */
/* #undef HAVE_DECL_GETACL */

/* Define to 1 if you have the declaration of `GETACLCNT', and to 0 if you
   don't. */
/* #undef HAVE_DECL_GETACLCNT */

/* Define to 1 if you have the declaration of `INT32_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_INT32_MAX 1

/* Define to 1 if you have the declaration of `INT32_MIN', and to 0 if you
   don't. */
#define HAVE_DECL_INT32_MIN 1

/* Define to 1 if you have the declaration of `INT64_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_INT64_MAX 1

/* Define to 1 if you have the declaration of `INT64_MIN', and to 0 if you
   don't. */
#define HAVE_DECL_INT64_MIN 1

/* Define to 1 if you have the declaration of `INTMAX_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_INTMAX_MAX 1

/* Define to 1 if you have the declaration of `INTMAX_MIN', and to 0 if you
   don't. */
#define HAVE_DECL_INTMAX_MIN 1

/* Define to 1 if you have the declaration of `SETACL', and to 0 if you don't.
   */
/* #undef HAVE_DECL_SETACL */

/* Define to 1 if you have the declaration of `SIZE_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_SIZE_MAX 1

/* Define to 1 if you have the declaration of `SSIZE_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_SSIZE_MAX 1

/* Define to 1 if you have the declaration of `strerror_r', and to 0 if you
   don't. */
#define HAVE_DECL_STRERROR_R 1

/* Define to 1 if you have the declaration of `UINT32_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_UINT32_MAX 1

/* Define to 1 if you have the declaration of `UINT64_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_UINT64_MAX 1

/* Define to 1 if you have the declaration of `UINTMAX_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_UINTMAX_MAX 1

/* Define to 1 if you have the declaration of `XATTR_NOFOLLOW', and to 0 if
   you don't. */
#define HAVE_DECL_XATTR_NOFOLLOW 1

/* Define to 1 if you have the <dirent.h> header file, and it defines `DIR'.
   */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have a dirfd function or macro */
#define HAVE_DIRFD 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you don't have `vprintf' but do have `_doprnt.' */
/* #undef HAVE_DOPRNT */

/* Define to 1 if nl_langinfo supports D_MD_ORDER */
#define HAVE_D_MD_ORDER 1

/* A possible errno value for invalid file format errors */
#define HAVE_EFTYPE 1

/* A possible errno value for invalid file format errors */
#define HAVE_EILSEQ 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <expat.h> header file. */
/* #undef HAVE_EXPAT_H */

/* Define to 1 if you have the <ext2fs/ext2_fs.h> header file. */
/* #undef HAVE_EXT2FS_EXT2_FS_H */

/* Define to 1 if you have the `extattr_get_fd' function. */
/* #undef HAVE_EXTATTR_GET_FD */

/* Define to 1 if you have the `extattr_get_file' function. */
/* #undef HAVE_EXTATTR_GET_FILE */

/* Define to 1 if you have the `extattr_get_link' function. */
/* #undef HAVE_EXTATTR_GET_LINK */

/* Define to 1 if you have the `extattr_list_fd' function. */
/* #undef HAVE_EXTATTR_LIST_FD */

/* Define to 1 if you have the `extattr_list_file' function. */
/* #undef HAVE_EXTATTR_LIST_FILE */

/* Define to 1 if you have the `extattr_list_link' function. */
/* #undef HAVE_EXTATTR_LIST_LINK */

/* Define to 1 if you have the `extattr_set_fd' function. */
/* #undef HAVE_EXTATTR_SET_FD */

/* Define to 1 if you have the `extattr_set_link' function. */
/* #undef HAVE_EXTATTR_SET_LINK */

/* Define to 1 if you have the `facl' function. */
/* #undef HAVE_FACL */

/* Define to 1 if you have the `fchdir' function. */
#define HAVE_FCHDIR 1

/* Define to 1 if you have the `fchflags' function. */
#define HAVE_FCHFLAGS 1

/* Define to 1 if you have the `fchmod' function. */
#define HAVE_FCHMOD 1

/* Define to 1 if you have the `fchown' function. */
#define HAVE_FCHOWN 1

/* Define to 1 if you have the `fcntl' function. */
#define HAVE_FCNTL 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fdopendir' function. */
#define HAVE_FDOPENDIR 1

/* Define to 1 if you have the `fgetea' function. */
/* #undef HAVE_FGETEA */

/* Define to 1 if you have the `fgetxattr' function. */
#define HAVE_FGETXATTR 1

/* Define to 1 if you have the `flistea' function. */
/* #undef HAVE_FLISTEA */

/* Define to 1 if you have the `flistxattr' function. */
#define HAVE_FLISTXATTR 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the `fsetea' function. */
/* #undef HAVE_FSETEA */

/* Define to 1 if you have the `fsetxattr' function. */
#define HAVE_FSETXATTR 1

/* Define to 1 if you have the `fstat' function. */
#define HAVE_FSTAT 1

/* Define to 1 if you have the `fstatat' function. */
#define HAVE_FSTATAT 1

/* Define to 1 if you have the `fstatfs' function. */
#define HAVE_FSTATFS 1

/* Define to 1 if you have the `fstatvfs' function. */
#define HAVE_FSTATVFS 1

/* Define to 1 if you have the `ftruncate' function. */
#define HAVE_FTRUNCATE 1

/* Define to 1 if you have the `futimens' function. */
#define HAVE_FUTIMENS 1

/* Define to 1 if you have the `futimes' function. */
#define HAVE_FUTIMES 1

/* Define to 1 if you have the `futimesat' function. */
/* #undef HAVE_FUTIMESAT */

/* Define to 1 if you have the `getea' function. */
/* #undef HAVE_GETEA */

/* Define to 1 if you have the `geteuid' function. */
#define HAVE_GETEUID 1

/* Define to 1 if you have the `getgrgid_r' function. */
#define HAVE_GETGRGID_R 1

/* Define to 1 if you have the `getgrnam_r' function. */
#define HAVE_GETGRNAM_R 1

/* Define to 1 if you have the `getpid' function. */
#define HAVE_GETPID 1

/* Define to 1 if you have the `getpwnam_r' function. */
#define HAVE_GETPWNAM_R 1

/* Define to 1 if you have the `getpwuid_r' function. */
#define HAVE_GETPWUID_R 1

/* Define to 1 if you have the `getvfsbyname' function. */
#define HAVE_GETVFSBYNAME 1

/* Define to 1 if you have the `getxattr' function. */
#define HAVE_GETXATTR 1

/* Define to 1 if you have the `gmtime_r' function. */
#define HAVE_GMTIME_R 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define if you have the iconv() function and it works. */
#define HAVE_ICONV 1

/* Define to 1 if you have the <iconv.h> header file. */
#define HAVE_ICONV_H 1

/* Define to 1 if the system has the type `intmax_t'. */
#define HAVE_INTMAX_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <io.h> header file. */
/* #undef HAVE_IO_H */

/* Define to 1 if you have the <langinfo.h> header file. */
#define HAVE_LANGINFO_H 1

/* Define to 1 if you have the `lchflags' function. */
#define HAVE_LCHFLAGS 1

/* Define to 1 if you have the `lchmod' function. */
#define HAVE_LCHMOD 1

/* Define to 1 if you have the `lchown' function. */
#define HAVE_LCHOWN 1

/* Define to 1 if you have the `lgetea' function. */
/* #undef HAVE_LGETEA */

/* Define to 1 if you have the `lgetxattr' function. */
/* #undef HAVE_LGETXATTR */

/* Define to 1 if you have the `acl' library (-lacl). */
/* #undef HAVE_LIBACL */

/* Define to 1 if you have the `bz2' library (-lbz2). */
#define HAVE_LIBBZ2 1

/* Define to 1 if you have the `charset' library (-lcharset). */
/* #undef HAVE_LIBCHARSET */

/* Define to 1 if you have the `crypto' library (-lcrypto). */
/* #undef HAVE_LIBCRYPTO */

/* Define to 1 if you have the `eay32' library (-leay32). */
/* #undef HAVE_LIBEAY32 */

/* Define to 1 if you have the `eay64' library (-leay64). */
/* #undef HAVE_LIBEAY64 */

/* Define to 1 if you have the `expat' library (-lexpat). */
/* #undef HAVE_LIBEXPAT */

/* Define to 1 if you have the `lz4' library (-llz4). */
/* #undef HAVE_LIBLZ4 */

/* Define to 1 if you have the `lzma' library (-llzma). */
#define HAVE_LIBLZMA 1

/* Define to 1 if you have the `lzo2' library (-llzo2). */
/* #undef HAVE_LIBLZO2 */

/* Define to 1 if you have the `md' library (-lmd). */
/* #undef HAVE_LIBMD */

/* Define to 1 if you have the `nettle' library (-lnettle). */
/* #undef HAVE_LIBNETTLE */

/* Define to 1 if you have the `pcre' library (-lpcre). */
/* #undef HAVE_LIBPCRE */

/* Define to 1 if you have the `pcreposix' library (-lpcreposix). */
/* #undef HAVE_LIBPCREPOSIX */

/* Define to 1 if you have the `regex' library (-lregex). */
/* #undef HAVE_LIBREGEX */

/* Define to 1 if you have the `richacl' library (-lrichacl). */
/* #undef HAVE_LIBRICHACL */

/* Define to 1 if you have the `xml2' library (-lxml2). */
#define HAVE_LIBXML2 1

/* Define to 1 if you have the <libxml/xmlreader.h> header file. */
/* #undef HAVE_LIBXML_XMLREADER_H */

/* Define to 1 if you have the <libxml/xmlwriter.h> header file. */
/* #undef HAVE_LIBXML_XMLWRITER_H */

/* Define to 1 if you have the `z' library (-lz). */
#define HAVE_LIBZ 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the `link' function. */
#define HAVE_LINK 1

/* Define to 1 if you have the <linux/fiemap.h> header file. */
/* #undef HAVE_LINUX_FIEMAP_H */

/* Define to 1 if you have the <linux/fs.h> header file. */
/* #undef HAVE_LINUX_FS_H */

/* Define to 1 if you have the <linux/magic.h> header file. */
/* #undef HAVE_LINUX_MAGIC_H */

/* Define to 1 if you have the <linux/types.h> header file. */
/* #undef HAVE_LINUX_TYPES_H */

/* Define to 1 if you have the `listea' function. */
/* #undef HAVE_LISTEA */

/* Define to 1 if you have the `listxattr' function. */
#define HAVE_LISTXATTR 1

/* Define to 1 if you have the `llistea' function. */
/* #undef HAVE_LLISTEA */

/* Define to 1 if you have the `llistxattr' function. */
/* #undef HAVE_LLISTXATTR */

/* Define to 1 if you have the <localcharset.h> header file. */
#define HAVE_LOCALCHARSET_H 1

/* Define to 1 if you have the `locale_charset' function. */
#define HAVE_LOCALE_CHARSET 1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the `localtime_r' function. */
#define HAVE_LOCALTIME_R 1

/* Define to 1 if the system has the type `long long int'. */
#define HAVE_LONG_LONG_INT 1

/* Define to 1 if you have the `lsetea' function. */
/* #undef HAVE_LSETEA */

/* Define to 1 if you have the `lsetxattr' function. */
/* #undef HAVE_LSETXATTR */

/* Define to 1 if you have the `lstat' function. */
#define HAVE_LSTAT 1

/* Define to 1 if `lstat' has the bug that it succeeds when given the
   zero-length file name argument. */
/* #undef HAVE_LSTAT_EMPTY_STRING_BUG */

/* Define to 1 if you have the `lutimes' function. */
#define HAVE_LUTIMES 1

/* Define to 1 if you have the <lz4hc.h> header file. */
/* #undef HAVE_LZ4HC_H */

/* Define to 1 if you have the <lz4.h> header file. */
/* #undef HAVE_LZ4_H */

/* Define to 1 if you have the <lzma.h> header file. */
#define HAVE_LZMA_H 1

/* Define to 1 if you have the `lzma_stream_encoder_mt' function. */
#define HAVE_LZMA_STREAM_ENCODER_MT 1

/* Define to 1 if you have the <lzo/lzo1x.h> header file. */
/* #undef HAVE_LZO_LZO1X_H */

/* Define to 1 if you have the <lzo/lzoconf.h> header file. */
/* #undef HAVE_LZO_LZOCONF_H */

/* Define to 1 if you have the `mbrtowc' function. */
#define HAVE_MBRTOWC 1

/* Define to 1 if you have the `mbr_gid_to_uuid' function. */
#define HAVE_MBR_GID_TO_UUID 1

/* Define to 1 if you have the `mbr_uid_to_uuid' function. */
#define HAVE_MBR_UID_TO_UUID 1

/* Define to 1 if you have the `mbr_uuid_to_id' function. */
#define HAVE_MBR_UUID_TO_ID 1

/* Define to 1 if you have the <md5.h> header file. */
/* #undef HAVE_MD5_H */

/* Define to 1 if you have the <membership.h> header file. */
#define HAVE_MEMBERSHIP_H 1

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the `mkdir' function. */
#define HAVE_MKDIR 1

/* Define to 1 if you have the `mkfifo' function. */
#define HAVE_MKFIFO 1

/* Define to 1 if you have the `mknod' function. */
#define HAVE_MKNOD 1

/* Define to 1 if you have the `mkstemp' function. */
#define HAVE_MKSTEMP 1

/* Define to 1 if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <nettle/aes.h> header file. */
/* #undef HAVE_NETTLE_AES_H */

/* Define to 1 if you have the <nettle/hmac.h> header file. */
/* #undef HAVE_NETTLE_HMAC_H */

/* Define to 1 if you have the <nettle/md5.h> header file. */
/* #undef HAVE_NETTLE_MD5_H */

/* Define to 1 if you have the <nettle/pbkdf2.h> header file. */
/* #undef HAVE_NETTLE_PBKDF2_H */

/* Define to 1 if you have the <nettle/ripemd160.h> header file. */
/* #undef HAVE_NETTLE_RIPEMD160_H */

/* Define to 1 if you have the <nettle/sha.h> header file. */
/* #undef HAVE_NETTLE_SHA_H */

/* Define to 1 if you have the `nl_langinfo' function. */
#define HAVE_NL_LANGINFO 1

/* Define to 1 if you have the `openat' function. */
#define HAVE_OPENAT 1

/* Define to 1 if you have the <openssl/evp.h> header file. */
/* #undef HAVE_OPENSSL_EVP_H */

/* Define to 1 if you have the <paths.h> header file. */
#define HAVE_PATHS_H 1

/* Define to 1 if you have the <pcreposix.h> header file. */
/* #undef HAVE_PCREPOSIX_H */

/* Define to 1 if you have the `pipe' function. */
#define HAVE_PIPE 1

/* Define to 1 if you have the `PKCS5_PBKDF2_HMAC_SHA1' function. */
/* #undef HAVE_PKCS5_PBKDF2_HMAC_SHA1 */

/* Define to 1 if you have the `poll' function. */
#define HAVE_POLL 1

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Define to 1 if you have the `posix_spawnp' function. */
#define HAVE_POSIX_SPAWNP 1

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have a POSIX compatible readdir_r */
#define HAVE_READDIR_R 1

/* Define to 1 if you have the `readlink' function. */
#define HAVE_READLINK 1

/* Define to 1 if you have the `readlinkat' function. */
#define HAVE_READLINKAT 1

/* Define to 1 if you have the `readpassphrase' function. */
#define HAVE_READPASSPHRASE 1

/* Define to 1 if you have the <readpassphrase.h> header file. */
#define HAVE_READPASSPHRASE_H 1

/* Define to 1 if you have the <regex.h> header file. */
#define HAVE_REGEX_H 1

/* Define to 1 if you have the `richacl_alloc' function. */
/* #undef HAVE_RICHACL_ALLOC */

/* Define to 1 if you have the `richacl_equiv_mode' function. */
/* #undef HAVE_RICHACL_EQUIV_MODE */

/* Define to 1 if you have the `richacl_free' function. */
/* #undef HAVE_RICHACL_FREE */

/* Define to 1 if you have the `richacl_get_fd' function. */
/* #undef HAVE_RICHACL_GET_FD */

/* Define to 1 if you have the `richacl_get_file' function. */
/* #undef HAVE_RICHACL_GET_FILE */

/* Define to 1 if you have the `richacl_set_fd' function. */
/* #undef HAVE_RICHACL_SET_FD */

/* Define to 1 if you have the `richacl_set_file' function. */
/* #undef HAVE_RICHACL_SET_FILE */

/* Define to 1 if you have the <ripemd.h> header file. */
/* #undef HAVE_RIPEMD_H */

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `setenv' function. */
#define HAVE_SETENV 1

/* Define to 1 if you have the `setlocale' function. */
#define HAVE_SETLOCALE 1

/* Define to 1 if you have the `setxattr' function. */
#define HAVE_SETXATTR 1

/* Define to 1 if you have the <sha256.h> header file. */
/* #undef HAVE_SHA256_H */

/* Define to 1 if you have the <sha512.h> header file. */
/* #undef HAVE_SHA512_H */

/* Define to 1 if you have the <sha.h> header file. */
/* #undef HAVE_SHA_H */

/* Define to 1 if you have the `sigaction' function. */
#define HAVE_SIGACTION 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the <spawn.h> header file. */
#define HAVE_SPAWN_H 1

/* Define to 1 if you have the `statfs' function. */
#define HAVE_STATFS 1

/* Define to 1 if you have the `statvfs' function. */
#define HAVE_STATVFS 1

/* Define to 1 if `stat' has the bug that it succeeds when given the
   zero-length file name argument. */
/* #undef HAVE_STAT_EMPTY_STRING_BUG */

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the `strerror_r' function. */
#define HAVE_STRERROR_R 1

/* Define to 1 if you have the `strftime' function. */
#define HAVE_STRFTIME 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strncpy_s' function. */
/* #undef HAVE_STRNCPY_S */

/* Define to 1 if you have the `strrchr' function. */
#define HAVE_STRRCHR 1

/* Define to 1 if the system has the type `struct richace'. */
/* #undef HAVE_STRUCT_RICHACE */

/* Define to 1 if the system has the type `struct richacl'. */
/* #undef HAVE_STRUCT_RICHACL */

/* Define to 1 if `f_namemax' is a member of `struct statfs'. */
/* #undef HAVE_STRUCT_STATFS_F_NAMEMAX */

/* Define to 1 if `f_iosize' is a member of `struct statvfs'. */
/* #undef HAVE_STRUCT_STATVFS_F_IOSIZE */

/* Define to 1 if `st_birthtime' is a member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_BIRTHTIME 1

/* Define to 1 if `st_birthtimespec.tv_nsec' is a member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_BIRTHTIMESPEC_TV_NSEC 1

/* Define to 1 if `st_blksize' is a member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_BLKSIZE 1

/* Define to 1 if `st_flags' is a member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_FLAGS 1

/* Define to 1 if `st_mtimespec.tv_nsec' is a member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC 1

/* Define to 1 if `st_mtime_n' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_MTIME_N */

/* Define to 1 if `st_mtime_usec' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_MTIME_USEC */

/* Define to 1 if `st_mtim.tv_nsec' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC */

/* Define to 1 if `st_umtime' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_UMTIME */

/* Define to 1 if `tm_gmtoff' is a member of `struct tm'. */
#define HAVE_STRUCT_TM_TM_GMTOFF 1

/* Define to 1 if `__tm_gmtoff' is a member of `struct tm'. */
/* #undef HAVE_STRUCT_TM___TM_GMTOFF */

/* Define to 1 if the system has the type `struct vfsconf'. */
#define HAVE_STRUCT_VFSCONF 1

/* Define to 1 if the system has the type `struct xvfsconf'. */
/* #undef HAVE_STRUCT_XVFSCONF */

/* Define to 1 if you have the `symlink' function. */
#define HAVE_SYMLINK 1

/* Define to 1 if you have the <sys/acl.h> header file. */
#define HAVE_SYS_ACL_H 1

/* Define to 1 if you have the <sys/cdefs.h> header file. */
#define HAVE_SYS_CDEFS_H 1

/* Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/ea.h> header file. */
/* #undef HAVE_SYS_EA_H */

/* Define to 1 if you have the <sys/extattr.h> header file. */
/* #undef HAVE_SYS_EXTATTR_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/mkdev.h> header file. */
/* #undef HAVE_SYS_MKDEV_H */

/* Define to 1 if you have the <sys/mount.h> header file. */
#define HAVE_SYS_MOUNT_H 1

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/poll.h> header file. */
#define HAVE_SYS_POLL_H 1

/* Define to 1 if you have the <sys/richacl.h> header file. */
/* #undef HAVE_SYS_RICHACL_H */

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/statfs.h> header file. */
/* #undef HAVE_SYS_STATFS_H */

/* Define to 1 if you have the <sys/statvfs.h> header file. */
#define HAVE_SYS_STATVFS_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/utime.h> header file. */
/* #undef HAVE_SYS_UTIME_H */

/* Define to 1 if you have the <sys/utsname.h> header file. */
#define HAVE_SYS_UTSNAME_H 1

/* Define to 1 if you have the <sys/vfs.h> header file. */
/* #undef HAVE_SYS_VFS_H */

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <sys/xattr.h> header file. */
#define HAVE_SYS_XATTR_H 1

/* Define to 1 if you have the `timegm' function. */
#define HAVE_TIMEGM 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the `tzset' function. */
#define HAVE_TZSET 1

/* Define to 1 if the system has the type `uintmax_t'. */
#define HAVE_UINTMAX_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `unsetenv' function. */
#define HAVE_UNSETENV 1

/* Define to 1 if the system has the type `unsigned long long'. */
#define HAVE_UNSIGNED_LONG_LONG 1

/* Define to 1 if the system has the type `unsigned long long int'. */
#define HAVE_UNSIGNED_LONG_LONG_INT 1

/* Define to 1 if you have the `utime' function. */
#define HAVE_UTIME 1

/* Define to 1 if you have the `utimensat' function. */
#define HAVE_UTIMENSAT 1

/* Define to 1 if you have the `utimes' function. */
#define HAVE_UTIMES 1

/* Define to 1 if you have the <utime.h> header file. */
#define HAVE_UTIME_H 1

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Define to 1 if you have the <wchar.h> header file. */
#define HAVE_WCHAR_H 1

/* Define to 1 if the system has the type `wchar_t'. */
#define HAVE_WCHAR_T 1

/* Define to 1 if you have the `wcrtomb' function. */
#define HAVE_WCRTOMB 1

/* Define to 1 if you have the `wcscmp' function. */
#define HAVE_WCSCMP 1

/* Define to 1 if you have the `wcscpy' function. */
#define HAVE_WCSCPY 1

/* Define to 1 if you have the `wcslen' function. */
#define HAVE_WCSLEN 1

/* Define to 1 if you have the `wctomb' function. */
#define HAVE_WCTOMB 1

/* Define to 1 if you have the <wctype.h> header file. */
#define HAVE_WCTYPE_H 1

/* Define to 1 if you have the <wincrypt.h> header file. */
/* #undef HAVE_WINCRYPT_H */

/* Define to 1 if you have the <windows.h> header file. */
/* #undef HAVE_WINDOWS_H */

/* Define to 1 if you have the <winioctl.h> header file. */
/* #undef HAVE_WINIOCTL_H */

/* Define to 1 if you have the `wmemcmp' function. */
#define HAVE_WMEMCMP 1

/* Define to 1 if you have the `wmemcpy' function. */
#define HAVE_WMEMCPY 1

/* Define to 1 if you have the `wmemmove' function. */
#define HAVE_WMEMMOVE 1

/* Define to 1 if you have a working EXT2_IOC_GETFLAGS */
/* #undef HAVE_WORKING_EXT2_IOC_GETFLAGS */

/* Define to 1 if you have a working FS_IOC_GETFLAGS */
/* #undef HAVE_WORKING_FS_IOC_GETFLAGS */

/* Define to 1 if you have the <zlib.h> header file. */
#define HAVE_ZLIB_H 1

/* Define to 1 if you have the `_ctime64_s' function. */
/* #undef HAVE__CTIME64_S */

/* Define to 1 if you have the `_fseeki64' function. */
/* #undef HAVE__FSEEKI64 */

/* Define to 1 if you have the `_get_timezone' function. */
/* #undef HAVE__GET_TIMEZONE */

/* Define to 1 if you have the `_localtime64_s' function. */
/* #undef HAVE__LOCALTIME64_S */

/* Define to 1 if you have the `_mkgmtime64' function. */
/* #undef HAVE__MKGMTIME64 */

/* Define as const if the declaration of iconv() needs const. */
#define ICONV_CONST 

/* Version number of libarchive as a single integer */
#define LIBARCHIVE_VERSION_NUMBER "3003002"

/* Version number of libarchive */
#define LIBARCHIVE_VERSION_STRING "3.3.2"

/* Define to 1 if `lstat' dereferences a symlink specified with a trailing
   slash. */
/* #undef LSTAT_FOLLOWS_SLASHED_SYMLINK */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Define to 1 if `major', `minor', and `makedev' are declared in <mkdev.h>.
   */
/* #undef MAJOR_IN_MKDEV */

/* Define to 1 if `major', `minor', and `makedev' are declared in
   <sysmacros.h>. */
/* #undef MAJOR_IN_SYSMACROS */

/* Define to '0x05020000' for Windows Server 2003 APIs. */
/* #undef NTDDI_VERSION */

/* Name of package */
#define PACKAGE "libarchive"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "libarchive-discuss@googlegroups.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libarchive"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libarchive 3.3.2"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libarchive"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "3.3.2"

/* Define to 1 if PCRE_STATIC needs to be defined. */
/* #undef PCRE_STATIC */

/* The size of `wchar_t', as computed by sizeof. */
#define SIZEOF_WCHAR_T 4

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if strerror_r returns char *. */
/* #undef STRERROR_R_CHAR_P */

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Version number of package */
#define VERSION "3.3.2"

/* Define to '0x0502' for Windows Server 2003 APIs. */
/* #undef WINVER */

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
/* #undef _LARGEFILE_SOURCE */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* Define for Solaris 2.5.1 so the uint64_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT64_T */

/* Define for Solaris 2.5.1 so the uint8_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT8_T */

/* Define to '0x0502' for Windows Server 2003 APIs. */
/* #undef _WIN32_WINNT */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to match typeof st_gid field of struct stat if <sys/types.h> doesn't
   define. */
/* #undef gid_t */

/* Define to `unsigned long' if <sys/types.h> does not define. */
/* #undef id_t */

/* Define to the type of a signed integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int16_t */

/* Define to the type of a signed integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int32_t */

/* Define to the type of a signed integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int64_t */

/* Define to the widest signed integer type if <stdint.h> and <inttypes.h> do
   not define. */
/* #undef intmax_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef mode_t */

/* Define to `long long' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to match typeof st_uid field of struct stat if <sys/types.h> doesn't
   define. */
/* #undef uid_t */

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint16_t */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */

/* Define to the type of an unsigned integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint64_t */

/* Define to the type of an unsigned integer type of width exactly 8 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint8_t */

/* Define to the widest unsigned integer type if <stdint.h> and <inttypes.h>
   do not define. */
/* #undef uintmax_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef uintptr_t */
