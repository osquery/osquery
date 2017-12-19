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
#include <sys/queue.h>

#include <libkern/OSMalloc.h>

#define TAGNAME "com.facebook.security.osquery.file_events"

#include "publishers.h"

static osquery_cqueue_t *cqueue = NULL;
static kauth_listener_t fileop_listener = NULL;

typedef struct subscription {
  osquery_file_event_subscription_t subscription;
  size_t pathlen;
  SLIST_ENTRY(subscription) next;
} subscription_t;

SLIST_HEAD(subscription_list, subscription);
static struct subscription_list sub_list = SLIST_HEAD_INITIALIZER(sub_list);

static osquery_file_action_t sub_actions = OSQUERY_FILE_ACTION_NONE;

static OSMallocTag malloc_tag = NULL;

static int fileop_scope_callback(kauth_cred_t credential,
                                 void *idata,
                                 kauth_action_t action,
                                 uintptr_t arg0,
                                 uintptr_t arg1,
                                 uintptr_t arg2,
                                 uintptr_t arg3) {
  osquery_file_action_t file_action = OSQUERY_FILE_ACTION_NONE;
  if (action == KAUTH_FILEOP_OPEN) {
    file_action = OSQUERY_FILE_ACTION_OPEN;
  } else if (action == KAUTH_FILEOP_CLOSE) {
    if (arg2 & KAUTH_FILEOP_CLOSE_MODIFIED) {
      file_action = OSQUERY_FILE_ACTION_CLOSE_MODIFIED;
    } else {
      file_action = OSQUERY_FILE_ACTION_CLOSE;
    }
  }

  vnode_t vp = (vnode_t)arg0;
  char *path = (char *)arg1;
  if (sub_actions & file_action && vp != NULL && path != NULL) {
    int subscribed_to_event = 0;
    subscription_t *sub = NULL;
    SLIST_FOREACH(sub, &sub_list, next) {
      if (sub->subscription.actions & file_action &&
          strncmp(path, sub->subscription.path, sub->pathlen) == 0) {
        subscribed_to_event = 1;
        break;
      }
    }
    if (subscribed_to_event) {
      // Someone is using a file in a way that we are subscribed to.
      int path_len = MAXPATHLEN;

      osquery_file_event_t *e = (osquery_file_event_t *)osquery_cqueue_reserve(
          cqueue, OSQUERY_FILE_EVENT, sizeof(osquery_file_event_t));
      if (e == NULL) {
        // Failed to reserve space for the event.
        return KAUTH_RESULT_DEFER;
      }

      e->action = OSQUERY_FILE_ACTION_NONE;
      if (action == KAUTH_FILEOP_OPEN) {
        e->action = OSQUERY_FILE_ACTION_OPEN;
      } else if (arg2 & KAUTH_FILEOP_CLOSE_MODIFIED) {
        e->action = OSQUERY_FILE_ACTION_CLOSE_MODIFIED;
      } else {
        e->action = OSQUERY_FILE_ACTION_CLOSE;
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
  }
  return KAUTH_RESULT_DEFER;
}

static int subscribe(osquery_cqueue_t *queue) {
  if (malloc_tag == NULL) {
    malloc_tag = OSMalloc_Tagalloc(TAGNAME, OSMT_DEFAULT);
    if (malloc_tag == NULL) {
      return -1;
    }
  }

  int err = 0;
  subscription_t *sub = OSMalloc(sizeof(subscription_t), malloc_tag);
  if (sub == NULL) {
    return -1;
  }

  cqueue = queue;
  if (fileop_listener == NULL) {
    fileop_listener =
        kauth_listen_scope(KAUTH_SCOPE_FILEOP, fileop_scope_callback, NULL);
  }
  if (fileop_listener == NULL) {
    err = -1;
    goto error_exit;
  }

  sub->pathlen = strnlen(sub->subscription.path, MAXPATHLEN);

  // Check if we are already subscribed to this event.
  subscription_t *sub_entry = NULL;
  SLIST_FOREACH(sub_entry, &sub_list, next) {
    if (sub_entry->subscription.actions == sub->subscription.actions &&
        strncmp(sub_entry->subscription.path,
                sub->subscription.path,
                MAXPATHLEN) == 0) {
      // Already subscribed.
      err = 0;
      goto error_exit;
    }
  }

  sub_actions |= sub->subscription.actions;

  SLIST_INSERT_HEAD(&sub_list, sub, next);
  return 0;
error_exit:
  OSFree(sub, sizeof(subscription_t), malloc_tag);
  return err;
}

static void unsubscribe() {
  if (fileop_listener) {
    kauth_unlisten_scope(fileop_listener);
    fileop_listener = NULL;
  }

  while (!SLIST_EMPTY(&sub_list)) {
    subscription_t *sub = SLIST_FIRST(&sub_list);
    SLIST_REMOVE_HEAD(&sub_list, next);
    OSFree(sub, sizeof(subscription_t), malloc_tag);
  }

  if (malloc_tag) {
    OSMalloc_Tagfree(malloc_tag);
    malloc_tag = NULL;
  }

  sub_actions = OSQUERY_FILE_ACTION_NONE;
}

osquery_kernel_event_publisher_t kernel_file_events_publisher = {
    .subscribe = &subscribe, .unsubscribe = &unsubscribe};
