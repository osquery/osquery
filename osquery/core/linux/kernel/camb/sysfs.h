#include <linux/kobject.h>

int expose_sysfs(void);
ssize_t text_segment_hash_show(struct kobject *, struct attribute *, char *);

struct camb_attr {
  struct attribute attr;
  int value;
};
