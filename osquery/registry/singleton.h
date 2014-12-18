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

namespace osquery {

// NOTE: T should have public or protected default ctor.
template <class T>
class Singleton : private T {
 public:
  static T& get() {
    // C++11 guarantees that initialization of static local
    // variables is thread-safe;  Moreover, GCC started to
    // provide the same guarantee long time ago.
    // http://cppwisdom.quora.com/Singletons-are-easy
    static Singleton<T> instance;
    return instance;
  }

 private:
  Singleton() {}
  ~Singleton() {}
};

} // namespace osquery
