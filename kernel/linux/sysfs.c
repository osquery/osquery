// Copyright 2004-present Facebook. All Rights Reserved.

#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "hash.h"
#include "sysfs.h"

struct kobject *camb_kobj;

extern ssize_t syscall_addr_modified_show(struct kobject *obj,
                                          struct attribute *attr,
                                          char *buf);
extern ssize_t text_segment_hash_show(struct kobject *obj,
                                      struct attribute *attr,
                                      char *buf);

struct kobj_attribute attr_syscall_addr_modified =
  __ATTR(syscall_addr_modified, 0444, syscall_addr_modified_show, NULL);

struct kobj_attribute attr_text_segment_hash =
  __ATTR(text_segment_hash, 0444, text_segment_hash_show, NULL);

struct attribute *camb_attrs[] = {
  &attr_text_segment_hash.attr,
  &attr_syscall_addr_modified.attr,
  NULL,
};

struct attribute_group attr_group = {
  .attrs = camb_attrs
};

int expose_sysfs(void) {
  int err = 0;
  camb_kobj = kobject_create_and_add("camb", kernel_kobj);
  if (camb_kobj) {
    if ((err = sysfs_create_group(camb_kobj, &attr_group)) != 0) {
      kobject_put(camb_kobj);
    }
  }
  return err;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("@unixist");
MODULE_DESCRIPTION("Detect kernel tampering");
