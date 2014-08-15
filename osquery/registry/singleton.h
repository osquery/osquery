// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_REGISTRY_SINGLETON_H
#define OSQUERY_REGISTRY_SINGLETON_H

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

#endif /* OSQUERY_REGISTRY_SINGLETON_H */
