#ifndef H_ARCHIVE
#define H_ARCHIVE

/** \ingroup payload
 * \file lib/rpmarchive.h
 * File archive (aka payload) API.
 */

#define RPMERR_CHECK_ERRNO    -32768

/** \ingroup payload
 * Error codes for archive and file handling
 */
enum rpmfilesErrorCodes {
	RPMERR_ITER_END		= -1,
	RPMERR_BAD_MAGIC	= -2,
	RPMERR_BAD_HEADER	= -3,
	RPMERR_HDR_SIZE	= -4,
	RPMERR_UNKNOWN_FILETYPE= -5,
	RPMERR_MISSING_FILE	= -6,
	RPMERR_DIGEST_MISMATCH	= -7,
	RPMERR_INTERNAL	= -8,
	RPMERR_UNMAPPED_FILE	= -9,
	RPMERR_ENOENT		= -10,
	RPMERR_ENOTEMPTY	= -11,
	RPMERR_FILE_SIZE	= -12,
	RPMERR_ITER_SKIP	= -13,
	RPMERR_EXIST_AS_DIR	= -14,

	RPMERR_OPEN_FAILED	= -32768,
	RPMERR_CHMOD_FAILED	= -32769,
	RPMERR_CHOWN_FAILED	= -32770,
	RPMERR_WRITE_FAILED	= -32771,
	RPMERR_UTIME_FAILED	= -32772,
	RPMERR_UNLINK_FAILED	= -32773,
	RPMERR_RENAME_FAILED	= -32774,
	RPMERR_SYMLINK_FAILED	= -32775,
	RPMERR_STAT_FAILED	= -32776,
	RPMERR_LSTAT_FAILED	= -32777,
	RPMERR_MKDIR_FAILED	= -32778,
	RPMERR_RMDIR_FAILED	= -32779,
	RPMERR_MKNOD_FAILED	= -32780,
	RPMERR_MKFIFO_FAILED	= -32781,
	RPMERR_LINK_FAILED	= -32782,
	RPMERR_READLINK_FAILED	= -32783,
	RPMERR_READ_FAILED	= -32784,
	RPMERR_COPY_FAILED	= -32785,
	RPMERR_LSETFCON_FAILED	= -32786,
	RPMERR_SETCAP_FAILED	= -32787,
};

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup payload
 * Return formatted error message on payload handling failure.
 * @param rc		error code
 * @return		formatted error string (malloced)
 */
char * rpmfileStrerror(int rc);

/** \ingroup payload
 * Get new file iterator for writing the archive content.
 * The returned rpmfi will only visit the files needing some content.
 * You need to provide the content using rpmfiArchiveWrite() or
 * rpmfiArchiveWriteFile(). Make sure to close the rpmfi with
 * rpmfiArchiveClose() to get the trailer written.
 * rpmfiSetFX() is not supported for this type of iterator.
 * @param fd		file
 * @param files         file info
 * @return		new rpmfi
 */
rpmfi rpmfiNewArchiveWriter(FD_t fd, rpmfiles files);

/** \ingroup payload
 * Get new file iterator for looping over the archive content.
 * Returned rpmfi visites files in the order they are read from the payload.
 * Content of the regular files can be retrieved with rpmfiArchiveRead() or
 * rpmfiArchiveReadToFile() when they are visited with rpmfiNext().
 * rpmfiSetFX() is not supported for this type of iterator.
 * @param fd		file
 * @param files         file info
 * @param itype		how to handle hard links. See rpmFileIter.
 * @return		new rpmfi
 */
    rpmfi rpmfiNewArchiveReader(FD_t fd, rpmfiles files, int itype);

/** \ingroup payload
 * Close payload archive
 * @param fi		file info
 * @return		> 0 on error
 */
int rpmfiArchiveClose(rpmfi fi);

/** \ingroup payload
 * Return current position in payload archive
 * @param fi		file info
 * @return		position
 */
rpm_loff_t rpmfiArchiveTell(rpmfi fi);

/** \ingroup payload
 * Write content into current file in archive
 * @param fi		file info
 * @param buf		pointer to content
 * @param size		number of bytes to write
 * @return		bytes actually written
 */
size_t rpmfiArchiveWrite(rpmfi fi, const void * buf, size_t size);

/** \ingroup payload
 * Write content from given file into current file in archive
 * @param fi		file info
 * @param fd		file descriptor of file to read
 * @return		> 0 on error
 */
int rpmfiArchiveWriteFile(rpmfi fi, FD_t fd);

/** \ingroup payload
 * Read content from current file in archive
 * @param fi		file info
 * @param buf		pointer to buffer
 * @param size		number of bytes to read
 * @return		bytes actually read
 */
size_t rpmfiArchiveRead(rpmfi fi, void * buf, size_t size);

/** \ingroup payload
 * Has current file content stored in the archive
 * @param fi            file info
 * @ return		1 for regular files but 0 for hardlinks without content
 */
int rpmfiArchiveHasContent(rpmfi fi);

/** \ingroup payload
 * Write content from current file in archive to a file
 * @param fi		file info
 * @param fd		file descriptor of file to write to
 * @param nodigest	omit checksum check if 1
 * @return		> 0 on error
 */
int rpmfiArchiveReadToFile(rpmfi fi, FD_t fd, int nodigest);

#ifdef __cplusplus
}
#endif

#endif	/* H_ARCHIVE */
