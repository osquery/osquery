/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/status/status.h>

namespace osquery {

template <typename ResourceAllocator, typename... ArgumentList>
class UniqueResource final : private ResourceAllocator {
 public:
  using ResourceType = typename ResourceAllocator::ResourceType;
  using ResourceAllocator::allocate;
  using ResourceAllocator::deallocate;

  UniqueResource() = default;

  virtual ~UniqueResource() override {
    release();
  }

  operator bool() const {
    static const ResourceType kNullResource{};
    return kNullResource != resource;
  }

  ResourceType get() const {
    return resource;
  }

  void reset(ResourceType resource) {
    release();
    this->resource = resource;
  }

  void release() {
    if (*this) {
      deallocate(resource);
    }
  }

  static Status create(UniqueResource& unique_resource,
                       const ArgumentList&... args) {
    ResourceType resource{};
    auto status = allocate(resource, args...);
    if (!status.ok()) {
      return status;
    }

    unique_resource.reset(resource);
    return Status::success();
  }

  UniqueResource(UniqueResource&& other);
  UniqueResource& operator=(UniqueResource&& other);

  UniqueResource(const UniqueResource&) = delete;
  UniqueResource& operator=(const UniqueResource&) = delete;

 private:
  ResourceType resource{};
};

} // namespace osquery
