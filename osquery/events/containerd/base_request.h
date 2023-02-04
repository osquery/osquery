/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <future>

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>

#include "client_interface.h"

#include <grpcpp/grpcpp.h>

namespace osquery {

template <typename ServiceClass, typename RPCInput, typename RPCOutput>
class BaseRequest final {
 public:
  class Output final : public IBaseStreamRequestOutput<RPCOutput> {
    struct PrivateData {
      std::future<Status> status;
      std::atomic_bool terminate{false};

      mutable std::mutex item_list_mutex;
      std::vector<RPCOutput> item_list;
    };

    std::unique_ptr<PrivateData> d;

   public:
    Output() : d(new PrivateData){};
    ~Output() override {
      if (d->status.valid()) {
        d->terminate = true;
        d->status.wait();
      }
    };

    bool running() const override {
      switch (d->status.wait_for(std::chrono::seconds(0U))) {
      case std::future_status::timeout:
      case std::future_status::deferred:
        return true;

      case std::future_status::ready:
        return false;
      }
      return true;
    };

    void terminate() override {
      d->terminate = true;
    };

    bool ready() const override {
      bool readable = false;

      {
        std::lock_guard<std::mutex> lock(d->item_list_mutex);
        readable = !d->item_list.empty();
      }

      return readable;
    };

    std::future<Status>& status() override {
      return d->status;
    };

    std::vector<RPCOutput> getData() override {
      std::vector<RPCOutput> item_list;

      {
        std::lock_guard<std::mutex> lock(d->item_list_mutex);

        item_list = std::move(d->item_list);
        d->item_list.clear();
      }

      return item_list;
    };

   private:
    std::atomic_bool& getTerminateFlagRef() {
      return d->terminate;
    };

    void setFutureStatus(std::future<Status> status) {
      d->status = std::move(status);
    };

    void addData(const RPCOutput& item) {
      std::lock_guard<std::mutex> lock(d->item_list_mutex);
      d->item_list.push_back(item);
    };

    friend class AsyncAPIClient;
    friend class BaseRequest<ServiceClass, RPCInput, RPCOutput>;
  };

  enum class RequestTag { StartCall, Read, Finish };

  using OutputRef =
      std::shared_ptr<BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output>;

  using ClientAsyncReaderInterface =
      grpc::ClientAsyncReaderInterface<RPCOutput>;

  using ClientAsyncReaderInterfaceRef =
      std::unique_ptr<ClientAsyncReaderInterface>;

  using RPCFactory = ClientAsyncReaderInterfaceRef (
      ServiceClass::StubInterface::*)(grpc::ClientContext*,
                                      const RPCInput&,
                                      grpc::CompletionQueue*);

  static std::shared_ptr<IBaseStreamRequestOutput<RPCOutput>> create(
      const std::string& address,
      RPCFactory rpc_factory,
      const RPCInput& input_parameters) {
    static auto L_worker = [](RPCFactory rpc_factory,
                              RPCInput input_parameters,
                              Output& output,
                              const std::string& address) -> Status {
      BaseRequest<ServiceClass, RPCInput, RPCOutput> request(
          rpc_factory, input_parameters, address, output.getTerminateFlagRef());

      return request.execute(output);
    };

    auto output_ref = std::make_shared<
        BaseRequest<ServiceClass, RPCInput, RPCOutput>::Output>();

    auto status = std::async(std::launch::async,
                             L_worker,
                             rpc_factory,
                             input_parameters,
                             std::ref(*output_ref.get()),
                             address);

    output_ref->setFutureStatus(std::move(status));
    return output_ref;
  }

  BaseRequest(RPCFactory rpc_factory,
              const RPCInput& input,
              const std::string& address,
              std::atomic_bool& terminate)
      : d(new PrivateData(terminate, rpc_factory, input, address)){};

  ~BaseRequest(){};

  std::atomic_bool& getTerminateFlagRef() {
    return d->terminate;
  };

  // Create the stub for communication
  Status execute(Output& output) {
    auto channel =
        grpc::CreateChannel(d->address_, grpc::InsecureChannelCredentials());

    auto stub = ServiceClass::NewStub(channel);

    grpc::ClientContext client_context;
    grpc::CompletionQueue completion_queue;

    auto response_reader = (*stub.*d->rpc_factory_)(
        &client_context, d->rpc_input_, &completion_queue);

    response_reader->StartCall(reinterpret_cast<void*>(RequestTag::StartCall));

    bool request_aborted = false;
    Status status;

    for (;;) {
      if (d->terminate_) {
        client_context.TryCancel();
        request_aborted = true;
      }

      void* current_raw_tag = nullptr;
      bool succeeded = false;
      auto timeout = std::chrono::system_clock::now() + std::chrono::seconds(1);

      auto s =
          completion_queue.AsyncNext(&current_raw_tag, &succeeded, timeout);
      if (s == grpc::CompletionQueue::SHUTDOWN) {
        request_aborted = true;
        break;

      } else if (s == grpc::CompletionQueue::TIMEOUT) {
        continue;
      }

      auto current_tag = static_cast<RequestTag>(
          reinterpret_cast<std::int64_t>(current_raw_tag));

      if (current_tag == RequestTag::StartCall && !succeeded) {
        return Status::failure("Failed to initialize the RPC call");
      }

      status = processNextEvent(
          current_tag, succeeded, *response_reader.get(), output);
      if (!status.ok()) {
        return status;
      }

      if (current_tag == RequestTag::Finish) {
        break;
      }
    }

    if (request_aborted) {
      return Status::failure("The request was aborted");
    }

    return status;
  }

 protected:
  struct PrivateData {
    PrivateData(std::atomic_bool& terminate,
                const RPCFactory& rpc_factory,
                const RPCInput& rpc_input,
                const std::string& address)
        : terminate_(terminate),
          rpc_factory_(rpc_factory),
          rpc_input_(rpc_input),
          address_(address) {}

    std::atomic_bool& terminate_;

    RPCFactory rpc_factory_;
    RPCInput rpc_input_;
    std::string address_;

    RPCOutput current_item_;
    grpc::Status grpc_status_;
  };
  std::unique_ptr<PrivateData> d;

  Status processNextEvent(RequestTag current_tag,
                          bool succeeded,
                          ClientAsyncReaderInterface& response_reader,
                          Output& output) {
    if (current_tag == RequestTag::StartCall) {
      if (!succeeded) {
        return Status::failure("Failed to initialize the RPC call");
      }

      response_reader.Read(&d->current_item_,
                           reinterpret_cast<void*>(RequestTag::Read));

      return Status::success();

    } else if (current_tag == RequestTag::Read) {
      bool terminate = false;

      if (succeeded) {
        output.addData(d->current_item_);
      } else {
        terminate = true;
      }

      if (terminate) {
        response_reader.Finish(&d->grpc_status_,
                               reinterpret_cast<void*>(RequestTag::Finish));
      } else {
        response_reader.Read(&d->current_item_,
                             reinterpret_cast<void*>(RequestTag::Read));
      }

      return Status::success();

    } else if (current_tag == RequestTag::Finish) {
      if (!d->grpc_status_.ok()) {
        return Status::failure("gRPC error");
      }

      return Status::success();

    } else {
      return Status::failure("Invalid event received");
    }
  }
};
} // namespace osquery
