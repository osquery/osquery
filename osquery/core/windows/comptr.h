/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <cassert>

namespace osquery {

template <class Interface, const IID* interface_id = &__uuidof(Interface)>
class ComPtr {
  Interface* ptr_{nullptr};

 public:
  class BlockIUnknownMethods : public Interface {
   private:
    using Interface::AddRef;
    using Interface::QueryInterface;
    using Interface::Release;
  };

  ComPtr() = default;

  explicit ComPtr(Interface* p) : ptr_(p) {
    if (ptr_) {
      ptr_->AddRef();
    }
  }

  ComPtr(const ComPtr<Interface, interface_id>& p) : ComPtr(p.get()) {}

  ~ComPtr() {
    static_assert(sizeof(ComPtr<Interface, interface_id>) == sizeof(Interface*),
                  ComPtrSize);

    release();
  }

  Interface* get() const {
    return ptr_;
  }

  explicit operator bool() const {
    return !!ptr_;
  }

  void release() {
    Interface* const temp = ptr_;
    if (temp) {
      ptr_ = nullptr;
      temp->Release();
    }
  }

  Interface* detach() {
    Interface* const p = ptr_;
    ptr_ = nullptr;
    return p;
  }

  void attach(Interface* p) {
    assert(!ptr_);
    ptr_ = p;
  }

  Interface** receive() {
    assert(!ptr_ && "pointer must be null");
    return &ptr_;
  }

  void** receiveVoid() {
    return reinterpret_cast<void**>(receive());
  }

  template <class Query>
  HRESULT queryInterface(Query** p) {
    assert(p);
    assert(ptr_);
    return ptr_->QueryInterface(p);
  }

  HRESULT queryInterface(const IID& iid, void** obj) {
    assert(p);
    assert(ptr_);
    return ptr_->QueryInterface(iid, obj);
  }

  HRESULT createInstance(const CLSID& clsid,
                         IUnknown* outer = nullptr,
                         DWORD context = CLSCTX_ALL) {
    HRESULT hr =
        ::CoCreateInstance(clsid, outer, context, *interface_id, receiveVoid());
    return hr;
  }

  BlockIUnknownMethods* operator->() const {
    assert(ptr_);
    return reinterpret_cast<BlockIUnknownMethods*>(ptr_);
  }

  ComPtr<Interface, interface_id>& operator=(
      const ComPtr<Interface, interface_id>& rhs) {
    return *this = rhs.ptr_;
  }

  Interface& operator*() const {
    assert(ptr_);
    return *ptr_;
  }

  bool operator==(const ComPtr<Interface, interface_id>& rhs) const {
    return ptr_ == rhs.get();
  }

  void swap(ComPtr<Interface, interface_id>& r) {
    Interface* tmp = ptr_;
    ptr_ = r.ptr_;
    r.ptr_ = tmp;
  }
};
} // namespace osquery
