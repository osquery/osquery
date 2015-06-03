/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <feeds.h>

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  int err = 0;
  if (argc < 2) {
    return -10;
  }

  int n = atoi(argv[1]);
  const char *filename = "/dev/osquery";
  int fd = open(filename, O_RDWR);
  if (fd < 0) {
    err = -11;
    goto error_exit;
  }

  for (uint32_t i = 0; i < 1000000; i ++) {
    if ((err = ioctl(fd, OSQUERY_IOCTL_TEST, &n))) {
      goto error_exit;
    }
  }

error_exit:
  if (fd >= 0) {
    close(fd);
  }
  printf("Producer task finished. err = %d\n", err);

  return err;
}

