/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

DECLARE_bool(disable_endpointsecurity);
DECLARE_bool(disable_endpointsecurity_fim);
DECLARE_string(es_fim_mute_path_literal);
DECLARE_string(es_fim_mute_path_prefix);

REGISTER(EndpointSecurityFileEventPublisher,
         "event_publisher",
         "endpointsecurity_fim")

Status EndpointSecurityFileEventPublisher::setUp() {
  if (__builtin_available(macos 10.15, *)) {
    if (FLAGS_disable_endpointsecurity) {
      return Status::failure(1,
                             "EndpointSecurity is disabled via configuration");
    }

    if (FLAGS_disable_endpointsecurity_fim) {
      return Status::failure(
          1, "EndpointSecurity FIM is disabled via configuration");
    }

    if (!FLAGS_es_fim_mute_path_literal.empty()) {
      boost::split(muted_path_literals_,
                   FLAGS_es_fim_mute_path_literal,
                   boost::is_any_of(","));
    }

    if (!FLAGS_es_fim_mute_path_prefix.empty()) {
      boost::split(muted_path_prefixes_,
                   FLAGS_es_fim_mute_path_prefix,
                   boost::is_any_of(","));
    }

    auto handler = ^(es_client_t* client, const es_message_t* message) {
      handleMessage(message);
    };

    auto result = es_new_client(&es_file_client_, handler);
    if (result == ES_NEW_CLIENT_RESULT_SUCCESS) {
      es_file_client_success_ = true;
      return Status::success();
    } else {
      return Status::failure(1, getEsNewClientErrorMessage(result));
    }
  } else {
    return Status::failure(
        1, "EndpointSecurity is only available on macOS 10.15 and higher");
  }
}

void EndpointSecurityFileEventPublisher::configure() {
  if (es_file_client_ == nullptr) {
    return;
  }

  auto result = es_clear_cache(es_file_client_);
  if (result != ES_CLEAR_CACHE_RESULT_SUCCESS) {
    VLOG(1) << "Couldn't clear cache for EndpointSecurity client";
    return;
  }

  for (auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    auto events = sc->es_file_event_subscriptions_;

    for (const auto& p : muted_path_literals_) {
      auto result = es_mute_path_literal(es_file_client_, p.c_str());
      if (result == ES_RETURN_ERROR) {
        VLOG(1) << "Unable to mute path literal: " << p;
      }
    }

    for (const auto& p : muted_path_prefixes_) {
      auto result = es_mute_path_prefix(es_file_client_, p.c_str());
      if (result == ES_RETURN_ERROR) {
        VLOG(1) << "Unable to mute path with prefix: " << p;
      }
    }

    for (const auto& p : default_muted_path_literals_) {
      auto result = es_mute_path_literal(es_file_client_, p.c_str());
      if (result == ES_RETURN_ERROR) {
        VLOG(1) << "Unable to mute default path: " << p;
      }
    }

    // mute ourselves
    audit_token_t self;
    mach_msg_type_number_t size = TASK_AUDIT_TOKEN_COUNT;
    auto kr = task_info(
        mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&self, &size);
    if (kr == KERN_SUCCESS) {
      es_mute_process(es_file_client_, &self);
    }

    auto es_sub = es_subscribe(es_file_client_, &events[0], events.size());
    if (es_sub != ES_RETURN_SUCCESS) {
      VLOG(1) << "Couldn't subscribe to EndpointSecurity subsystem";
    }
  }
}

bool EndpointSecurityFileEventPublisher::shouldFire(
    const EndpointSecurityFileSubscriptionContextRef& sc,
    const EndpointSecurityFileEventContextRef& ec) const {
  return true;
}

void EndpointSecurityFileEventPublisher::tearDown() {
  if (es_file_client_ == nullptr) {
    return;
  }
  es_unsubscribe_all(es_file_client_);
  if (es_file_client_success_) {
    auto result = es_delete_client(es_file_client_);
    if (result != ES_RETURN_SUCCESS) {
      VLOG(1) << "endpointsecurity_fim: error tearing down es_client";
    }
    es_file_client_ = nullptr;
  }
}

void EndpointSecurityFileEventPublisher::handleMessage(
    const es_message_t* message) {
  if (message == nullptr) {
    return;
  }

  if (message->action_type == ES_ACTION_TYPE_AUTH) {
    return;
  }
  auto ec = createEventContext();
  ec->version = message->version;
  if (ec->version >= 2) {
    ec->seq_num = message->seq_num;
  }

  if (ec->version >= 4) {
    ec->global_seq_num = message->global_seq_num;
  }

  getProcessProperties(message->process, ec);

  switch (message->event_type) {
  case ES_EVENT_TYPE_NOTIFY_CREATE: {
    ec->event_type = "create";
    if (message->event.create.destination_type ==
        ES_DESTINATION_TYPE_EXISTING_FILE) {
      ec->filename = getStringFromToken(
          &message->event.create.destination.existing_file->path);
    } else {
      std::string filename = getStringFromToken(
          &message->event.create.destination.new_path.dir->path);
      filename += '/';
      filename += getStringFromToken(
          &message->event.create.destination.new_path.filename);
      ec->filename = filename;
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_WRITE: {
    ec->event_type = "write";
    ec->filename = getStringFromToken(&message->event.write.target->path);
  } break;
  case ES_EVENT_TYPE_NOTIFY_RENAME: {
    ec->event_type = "rename";
    ec->filename = getStringFromToken(&message->event.rename.source->path);
    if (message->event.rename.destination_type ==
        ES_DESTINATION_TYPE_EXISTING_FILE) {
      ec->dest_filename = getStringFromToken(
          &message->event.rename.destination.existing_file->path);
    } else {
      std::string filename = getStringFromToken(
          &message->event.rename.destination.new_path.dir->path);
      filename += '/';
      filename += getStringFromToken(
          &message->event.rename.destination.new_path.filename);
      ec->dest_filename = filename;
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_TRUNCATE: {
    ec->event_type = "truncate";
    ec->filename = getStringFromToken(&message->event.truncate.target->path);
  } break;
  default:
    VLOG(1) << "endpointsecurity_fim: unexpected event " << message->event_type;
    break;
  }
  EventFactory::fire<EndpointSecurityFileEventPublisher>(ec);
}

} // namespace osquery