#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

/* Crypto */
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/sha.h>

#include "hash.h"

unsigned long *begin_text_addr = (void *) 0xffffffff81000000;
unsigned long *end_text_addr = (void *) 0xffffffff82000000;

unsigned char *kernel_text_hash(void) {
  return (unsigned char *) hash_data((void *) begin_text_addr,
                                     end_text_addr - begin_text_addr);
}

unsigned char *hash_data(const void *data, size_t len) {
  struct scatterlist sg;
  struct hash_desc desc;
  size_t out_len = SHA1_DIGEST_SIZE * 2 + 1;
  unsigned char hashtext[SHA1_DIGEST_SIZE];
  unsigned char *hashtext_out = kmalloc(out_len, GFP_KERNEL);

  if (!hashtext_out) {
    printk(KERN_INFO "Could not allocate space for hash\n");
    return NULL;
  }

  sg_init_one(&sg, data, len);
  desc.flags = 0;
  desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);

  crypto_hash_init(&desc);
  crypto_hash_update(&desc, &sg, sg.length);
  crypto_hash_final(&desc, hashtext);

  snprintf(hashtext_out,
           out_len,
           "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           hashtext[0], hashtext[1], hashtext[2], hashtext[3], 
           hashtext[4], hashtext[5], hashtext[6], hashtext[7], 
           hashtext[8], hashtext[9], hashtext[10], hashtext[11], 
           hashtext[12], hashtext[13], hashtext[14], hashtext[15], 
           hashtext[16], hashtext[17], hashtext[18], hashtext[19]
  );

  if (desc.tfm) {
    crypto_free_hash(desc.tfm);
  }

  return hashtext_out;
}

ssize_t text_segment_hash_show(struct kobject *obj,
                               struct attribute *attr,
                               char *buf) {
  ssize_t ret;
  char *hash = kernel_text_hash();

  if (hash) {
    ret = scnprintf(buf, PAGE_SIZE, "%s\n", hash);
    kfree(hash);
  } else {
    ret = -1;
  }

  return ret;
}
