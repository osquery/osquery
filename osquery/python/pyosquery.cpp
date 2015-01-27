/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>

#include <boost/python.hpp>

BOOST_PYTHON_MODULE(pyosquery) {
  using boost::python::def;
  using boost::python::scope;
  Py_Initialize();

  def("get_hostname", &osquery::getHostname);
  def("generate_host_uuid", &osquery::generateHostUuid);
  def("get_unix_time", &osquery::getUnixTime);
  def("get_ascii_time", &osquery::getAsciiTime);

  // TypeError: No to_python (by-value) converter found for C++ type:
  //   std::__1::vector<boost::filesystem::path, std::__1::allocator<boost::filesystem::path> >
  // def("get_home_directories", &osquery::getHomeDirectories);

  scope().attr("version") = osquery::kVersion;
}
