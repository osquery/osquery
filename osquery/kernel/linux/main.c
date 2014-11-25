#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <linux/kobject.h>
#include <asm/syscall.h>

#include "sysfs.h"
#include "hash.h"
#ifdef _HIDE_ME
  #include "hide.h"
#endif

extern struct kobject *camb_kobj;
char *module_str = "camb";

static unsigned long **syscall_table = (unsigned long **) SYSCALL_BASE_ADDR;
static unsigned long *syscall_table_copy[NR_syscalls];
int (*orig_init_module)(void *, unsigned long, const char *);

/* Allow writes to executable memory pages */
void en_mem_wr(void) {
  write_cr0(read_cr0() & (~0x10000));
}

void dis_mem_wr(void) {
  write_cr0(read_cr0() | 0x10000);
}

int syscall_addr_modified_show(struct kobject *obj,
                               struct attribute *attr,
                               char *buf) {
  unsigned int i = -1, mod = 0, ret;

  while(++i < NR_syscalls)
    if (syscall_table[i] != syscall_table_copy[i])
      mod = 1;
  ret = scnprintf(buf, PAGE_SIZE, "%d\n", mod);

  return ret;
}

/* Copy the system call pointer table  */
void grab_syscall_table(void) {
  unsigned int i;
  for (i = 0; i < NR_syscalls; i++)
    syscall_table_copy[i] = syscall_table[i];
}

int our_init_module(void *image, unsigned long len, const char *params) {
  int ret;
  unsigned char *h;
  unsigned char *image_tmp = kmalloc(len, GFP_KERNEL);
  ret = copy_from_user(image_tmp, image, len);
  if (ret) {
    printk(KERN_ERR "[%s] our_init_module: copy error\n", module_str);
  } else {
    h = hash_data(image_tmp, len);
    if (h) {
      printk(KERN_INFO "module loaded: %s\n", h);
      kfree(h);
    }
  }
  return orig_init_module(image, len, params);
}

void hook_init_module(void) {
  orig_init_module = syscall_table[__NR_init_module];

  en_mem_wr();
  syscall_table[__NR_init_module] = our_init_module;
  dis_mem_wr();
}

void unhook_init_module(void) {
  en_mem_wr();
  syscall_table[__NR_init_module] = orig_init_module;
  dis_mem_wr();
}

static int __init camb_init(void) {
  printk(KERN_INFO "[%s] init\n", module_str);

  if (expose_sysfs()) {
    printk(KERN_ERR "Cannot expose self to sysfs\n");
    return -1;
  }

  /* Hide the fact that we're monitoring the system for tampering */
#ifdef _HIDE_ME
  hide_me();
#endif

/* Syscall hooks must be placed before grab_syscall_table() is called in order to
 * establish a known baseline
 */
  hook_init_module();
  grab_syscall_table();

  return 0;
}

static void __exit camb_exit(void) {
  printk(KERN_INFO "[%s] exit\n", module_str);

  if (camb_kobj) {
    kobject_put(camb_kobj);
  }

  unhook_init_module();
}

module_init(camb_init);
module_exit(camb_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("@unixist");
MODULE_DESCRIPTION("Detect kernel tampering");
