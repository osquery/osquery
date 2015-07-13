/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/kauth.h>
#include <sys/vnode.h>

#include "publishers.h"

static osquery_cqueue_t *cqueue = NULL;
static kauth_listener_t fileop_listener = NULL;

static int fileop_scope_callback(kauth_cred_t credential,
                                 void *idata,
                                 kauth_action_t action,
                                 uintptr_t arg0,
                                 uintptr_t arg1,
                                 uintptr_t arg2,
                                 uintptr_t arg3) {
  vnode_t vp = (vnode_t)arg0;
  if (action == KAUTH_FILEOP_EXEC && vp != NULL) {
    // Someone is executing a file.
    int path_len = MAXPATHLEN;

    osquery_process_event_t *e =
        (osquery_process_event_t *)osquery_cqueue_reserve(
            cqueue, OSQUERY_PROCESS_EVENT);
    if (e == NULL) {
      // Failed to reserve space for the event.
      return KAUTH_RESULT_DEFER;
    }
    e->pid = proc_selfpid();
    e->ppid = proc_selfppid();
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

    e->uid = kauth_cred_getruid(credential);
    e->euid = kauth_cred_getuid(credential);

    e->gid = kauth_cred_getrgid(credential);
    e->egid = kauth_cred_getgid(credential);

    vn_getpath(vp, e->path, &path_len);

    osquery_cqueue_commit(cqueue, e);
  }
  return KAUTH_RESULT_DEFER;
}

static int subscribe(osquery_cqueue_t *queue, void *udata) {
  cqueue = queue;
  if (fileop_listener != NULL) {
    return -1;
  }

  fileop_listener =
      kauth_listen_scope(KAUTH_SCOPE_FILEOP, fileop_scope_callback, NULL);

  return 0;
}

static void unsubscribe() {
  if (fileop_listener) {
    kauth_unlisten_scope(fileop_listener);
    fileop_listener = NULL;
  }
}

osquery_kernel_event_publisher_t process_events_publisher = {
  .subscribe = &subscribe,
  .unsubscribe = &unsubscribe
};
