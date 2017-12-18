/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/imgact.h>
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>

#include "publishers.h"

static osquery_cqueue_t *cqueue = NULL;

#define MAX_VECTOR_LENGTH 4096

static inline int str_num(char *buf, size_t length) {
  int strs = 0;
  char *end = buf + length;
  while (buf < end) {
    if (*buf == '\0') {
      strs++;
    }
    buf++;
  }
  return strs;
}

static int process_cred_label_update_execvew(kauth_cred_t old_cred,
                                             kauth_cred_t new_cred,
                                             struct proc *p,
                                             struct vnode *vp,
                                             off_t offset,
                                             struct vnode *scriptvp,
                                             struct label *vnodelabel,
                                             struct label *scriptvnodelabel,
                                             struct label *execlabel,
                                             u_int *csflags,
                                             void *macpolicyattr,
                                             size_t macpolicyattrlen,
                                             int *disjointp) {
  int path_len = MAXPATHLEN;

  if (!vnode_isreg(vp)) {
    goto error_exit;
  }

  // Determine address of image_params based off of csflags pointer. (HACKY)
  struct image_params *img =
      (struct image_params *)((char *)csflags -
                              offsetof(struct image_params, ip_csflags));

  // Find the length of arg and env we will copy.
  size_t arg_length =
      MIN(MAX_VECTOR_LENGTH, img->ip_endargv - img->ip_startargv);
  size_t env_length = MIN(MAX_VECTOR_LENGTH, img->ip_endenvv - img->ip_endargv);

  osquery_process_event_t *e =
      (osquery_process_event_t *)osquery_cqueue_reserve(
          cqueue,
          OSQUERY_PROCESS_EVENT,
          sizeof(osquery_process_event_t) + arg_length + env_length);

  if (!e) {
    goto error_exit;
  }
  // Copy the arg and env vectors.
  e->argv_offset = 0;
  e->envv_offset = arg_length;

  e->arg_length = arg_length;
  e->env_length = env_length;

  memcpy(&(e->flexible_data[e->argv_offset]), img->ip_startargv, arg_length);
  memcpy(&(e->flexible_data[e->envv_offset]), img->ip_endargv, env_length);

  e->actual_argc = img->ip_argc;
  e->actual_envc = img->ip_envc;

  // Calculate our argc and envc based on the number of null bytes we find in
  // the buffer.
  e->argc = MIN(e->actual_argc,
                str_num(&(e->flexible_data[e->argv_offset]), arg_length));
  e->envc = MIN(e->actual_envc,
                str_num(&(e->flexible_data[e->envv_offset]), env_length));

  e->pid = proc_pid(p);
  e->ppid = proc_ppid(p);
  e->owner_uid = 0;
  e->owner_gid = 0;
  e->mode = -1;
  vfs_context_t context = vfs_context_create(NULL);
  if (context) {
    struct vnode_attr vattr = {0};
    VATTR_INIT(&vattr);
    VATTR_WANTED(&vattr, va_uid);
    VATTR_WANTED(&vattr, va_gid);
    VATTR_WANTED(&vattr, va_mode);
    VATTR_WANTED(&vattr, va_create_time);
    VATTR_WANTED(&vattr, va_access_time);
    VATTR_WANTED(&vattr, va_modify_time);
    VATTR_WANTED(&vattr, va_change_time);

    if (vnode_getattr(vp, &vattr, context) == 0) {
      e->owner_uid = vattr.va_uid;
      e->owner_gid = vattr.va_gid;
      e->mode = vattr.va_mode;
      e->create_time = vattr.va_create_time.tv_sec;
      e->access_time = vattr.va_access_time.tv_sec;
      e->modify_time = vattr.va_modify_time.tv_sec;
      e->change_time = vattr.va_change_time.tv_sec;
    }

    vfs_context_rele(context);
  }

  e->uid = kauth_cred_getruid(new_cred);
  e->euid = kauth_cred_getuid(new_cred);

  e->gid = kauth_cred_getrgid(new_cred);
  e->egid = kauth_cred_getgid(new_cred);

  vn_getpath(vp, e->path, &path_len);

  osquery_cqueue_commit(cqueue, e);
error_exit:

  return 0;
}

static mac_policy_handle_t handle = 0;

static struct mac_policy_ops exec_ops = {.mpo_cred_label_update_execve =
                                             process_cred_label_update_execvew};

static struct mac_policy_conf policy_conf = {
    .mpc_name = "osquery_process_events",
    .mpc_fullname = "Osquery Process Events",
    .mpc_labelnames = NULL,
    .mpc_labelname_count = 0,
    .mpc_ops = &exec_ops,
    .mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK,
    .mpc_field_off = NULL,
    .mpc_runtime_flags = 0};

static int subscribe(osquery_cqueue_t *queue) {
  cqueue = queue;
  if (handle != 0) {
    return -1;
  }

  mac_policy_register(&policy_conf, &handle, NULL);

  return 0;
}

static void unsubscribe() {
  if (handle) {
    mac_policy_unregister(handle);
    handle = 0;
  }
}

osquery_kernel_event_publisher_t process_events_publisher = {
    .subscribe = &subscribe, .unsubscribe = &unsubscribe};
