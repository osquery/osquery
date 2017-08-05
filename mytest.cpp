#include <stdio.h>
#include <string.h>
#include <iostream>
#include <cstdint>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdio.h>

const char *errno_name_list[35] = {
  NULL,
  "EPERM",
  "ENOENT",
  "ESRCH",
  "EINTR",
  "EIO",
  "ENXIO",
  "E2BIG",
  "ENOEXEC",
  "EBADF",
  "ECHILD",
  "EAGAIN",
  "ENOMEM",
  "EACCES",
  "EFAULT",
  "ENOTBLK",
  "EBUSY",
  "EEXIST",
  "EXDEV",
  "ENODEV",
  "ENOTDIR",
  "EISDIR",
  "EINVAL",
  "ENFILE",
  "EMFILE",
  "ENOTTY",
  "ETXTBSY",
  "EFBIG",
  "ENOSPC",
  "ESPIPE",
  "EROFS",
  "EMLINK",
  "EPIPE",
  "EDOM",
  "ERANGE"
};

/*
. __NR_link
. __NR_linkat
. __NR_symlink
. __NR_symlinkat
- __NR_readlink
- __NR_readlinkat


x __NR_unlink
x __NR_unlinkat


. __NR_rename
. __NR_renameat
. __NR_renameat2


x __NR_mknod
x __NR_mknodat
x __NR_open
x __NR_openat
x __NR_open_by_handle_at
x __NR_name_to_handle_at
x __NR_close
x __NR_dup
x __NR_dup2
x __NR_dup3


  __NR_pread64
  __NR_preadv
x __NR_read
  __NR_readv


x __NR_mmap
- __NR_mremap               no need to support it, as it required mmap() first and doesn't accept 'prot' param
x __NR_munmap
- __NR_remap_file_pages     accepts a 'prot' param but let's assume it uses the initial prot from mmap()....it's also deprecated and on x64 it's (slowly) emulated from kernel


x __NR_write
  __NR_writev
  __NR_pwrite64
  __NR_pwritev
*/

int main() {
  printf("pid: %d, 0x%x\n", getpid(), getpid());

  std::cout << "Removing old files..." << std::endl;
  unlink("/home/alessandro/test_file");
  unlink("/home/alessandro/test_file1");
  unlink("/home/alessandro/test_file2");
  unlink("/home/alessandro/test_file3");
  unlink("/home/alessandro/test_file4");
  unlink("/home/alessandro/test_file5");
  unlink("/home/alessandro/test_file6");
  unlink("/home/alessandro/test_file7");
  unlink("/home/alessandro/test_file8");
  unlink("/home/alessandro/test_link0");
  unlink("/home/alessandro/test_link1");
  unlink("/home/alessandro/test_link2");
  unlink("/home/alessandro/test_link3");
  std::cout << "Creating test file..." << std::endl;
  std::system("date > /home/alessandro/test_file");
  std::system("date > /home/alessandro/test_file5");
  std::cout << "Press return to start the test" << std::endl;
  getchar();

  errno = 0;
  if (rename("/home/alessandro/test_file5", "/home/alessandro/test_file6") != 0) {
    printf("Failed to rename the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  DIR *dir2 = opendir("/home/alessandro");
  if (dir2 == NULL) {
    printf("opendir() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  int dir_fd2 = dirfd(dir2);
  if (dir_fd2 == -1) {
    printf("dirfd() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  if (renameat(dir_fd2, "test_file6", dir_fd2, "test_file7") != 0) {
    printf("Failed to renameat the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  if (syscall(__NR_renameat2, dir_fd2, "test_file7", dir_fd2, "test_file8", 0) != 0) {
    printf("Failed to renameat the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  if (link("/home/alessandro/test_file8", "/home/alessandro/test_link0") != 0) {
    printf("Failed to link the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  if (symlink("/home/alessandro/test_file8", "/home/alessandro/test_link1") != 0) {
    printf("Failed to symlink the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  if (linkat(dir_fd2, "/home/alessandro/test_file8", dir_fd2, "/home/alessandro/test_link2", 0) != 0) {
    printf("Failed to link the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  if (symlinkat("/home/alessandro/test_file8", dir_fd2, "/home/alessandro/test_link3") != 0) {
    printf("Failed to symlink the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  int fd = open("/home/alessandro/test_file", O_RDWR | O_CREAT);
  if (fd == -1) {
    printf("Failed to open the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  char buffer[1024] = {};

  errno = 0;
  if (read(fd, buffer, 10) == -1) {
    printf("Failed to read the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  if (write(fd, buffer, sizeof(buffer)) == -1) {
    printf("Failed to write the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  if (pread(fd, buffer, 10, 1) == -1) {
    printf("Failed to pread the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  if (pwrite(fd, buffer, sizeof(buffer), 1) == -1) {
    printf("Failed to pwrite the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  int fd_copy1 = dup(fd);
  if (fd_copy1 == -1) {
    printf("dup() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  int fd_copy2 = dup2(fd, 10);
  if (fd_copy2 == -1) {
    printf("dup2() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  int fd_copy3 = dup3(fd, 11, 0);
  if (fd_copy3 == -1) {
    printf("dup3() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  int fd2 = openat(0, "/home/alessandro/test_file", 0);
  if (fd2 == -1) {
    printf("openat() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  std::uint8_t file_handle_buffer[1024] = {};
  struct file_handle *handle_ptr = reinterpret_cast<struct file_handle *>(file_handle_buffer);
  handle_ptr->handle_bytes = 128;

  int mount_id = 0;

  errno = 0;
  DIR *dir = opendir("/home/alessandro");
  if (dir == NULL) {
    printf("opendir() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  int dir_fd = dirfd(dir);
  if (dir_fd == -1) {
    printf("dirfd() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  if (name_to_handle_at(dir_fd, "/home/alessandro/test_file", handle_ptr, &mount_id, 0) != 0) {
    std::cout << errno << std::endl;
    printf("name_to_handle_at() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  int fd3 = open_by_handle_at(AT_FDCWD, handle_ptr, O_RDWR);
  if (fd3 == -1) {
    printf("open_by_handle_at() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  int mmap_protection_flags = PROT_READ | PROT_WRITE | PROT_EXEC;
  printf("mmap protection flags: %x\n", mmap_protection_flags);

  int mmap_flags = MAP_SHARED;
  printf("mmap flags: %x\n", mmap_flags);

  errno = 0;
  void *address = mmap(NULL, 10, mmap_protection_flags, mmap_flags, fd, 0);
  if (address == MAP_FAILED) {
    printf("Failed to map the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  if (munmap(address, 10) == -1) {
    printf("Failed to unmap the file. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  close(fd);
  if (errno != 0) {
    printf("close() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  fd = mknod("/home/alessandro/test_file2", S_IFREG | 0644, 0);
  if (fd == -1) {
      std::cout << "mknod failed with errno " << errno << std::endl;
      return 1;
  }

  errno = 0;
  dir = opendir("/home/alessandro/");
  if (dir == NULL) {
    printf("opendir() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  dir_fd = dirfd(dir);
  if (dir_fd == -1) {
    printf("dirfd() failed. Errno: %s\n", errno_name_list[errno]);
    return 1;
  }

  errno = 0;
  fd = mknodat(dir_fd, "test_file3", S_IFREG | 0644, 0);
  if (fd == -1) {
      std::cout << "mknodat failed with errno " << errno << std::endl;
      return 1;
  }

  errno = 0;
  fd = creat("/home/alessandro/test_file4", S_IFREG | 0644);
  if (fd == -1) {
      std::cout << "creat failed with errno " << errno << std::endl;
      return 1;
  }

  errno = 0;
  if (unlink("/home/alessandro/test_file4") != 0) {
    std::cout << "unlink failed with errno " << errno << std::endl;
    return 1;
  }

  errno = 0;
  if (unlinkat(dir_fd, "test_file3", 0) != 0) {
      std::cout << "unlinkat failed with errno " << errno << std::endl;
      return 1;
  }

  return 0;
}

