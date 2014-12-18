/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 
#pragma once

#include <boost/noncopyable.hpp>

#include "osquery/registry/registry_template.h"

namespace osquery {

class InitRegistry : public RegistryTemplate<> {
 public:
  /**
   * Singleton.
   */
  static InitRegistry& get() {
    static InitRegistry instance; // Thread-safe.
    return instance;
  }

 private:
  InitRegistry() {}
};

/**
 * The most standard way to register an init func is to use this class
 * as a static instance in some file to ensure the function gets called
 * once main actually begins.
 *
 * Examples:
 *
 *   static RegisterInitFunc reg1(&setupFancyTable);
 *   static RegisterInitFunc reg2(std::bind(&setupSomething, 10, 15));
 *   static RegisterInitFunc reg3([] { setupSomethingElse(20, 25); });
 *
 */
struct RegisterInitFunc : private boost::noncopyable {
  explicit RegisterInitFunc(InitRegistry::Func func,
                            int priority = InitRegistry::kDefaultPriority) {
    InitRegistry::get().registerFunc(std::move(func), priority);
  }
};

} // namespace osquery
