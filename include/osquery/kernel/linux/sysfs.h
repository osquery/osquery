// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <linux/kobject.h>

/**
 * @brief XXX
 *
 * @param foo this is what foo does
 *
 * @return XXX
 */
int expose_sysfs(void);

/**
 * @brief XXX
 *
 * @param foo this is what foo does
 * @param bar this is what bar does
 * @param baz this is what baz does
 *
 * @return XXX
 */
ssize_t text_segment_hash_show(struct kobject *, struct attribute *, char *);


/**
 * @brief XXX
 */
struct camb_attr {
  /// This is what this is
  struct attribute attr;

  /// This is what that is
  int value;
};
