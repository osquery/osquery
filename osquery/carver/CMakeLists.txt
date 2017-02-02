ADD_OSQUERY_LIBRARY(TRUE osquery_acquisition
  carver.cpp
)

ADD_OSQUERY_LINK_ADDITIONAL("archive")
#ADD_OSQUERY_LINK_ADDITIONAL("boost_iostreams")

#ADD_OSQUERY_LIBRARY(FALSE osquery_acquisition_plugins
#  plugins/tls.cpp
#)
