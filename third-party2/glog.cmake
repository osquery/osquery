get_source_path("glog" glog_source_path)

ExternalProject_Add(
  glog
  URL https://google-glog.googlecode.com/files/glog-0.3.3.tar.gz
  URL_HASH SHA1=ed40c26ecffc5ad47c618684415799ebaaa30d65
  CONFIGURE_COMMAND ${glog_source_path}/configure --prefix=${third_party_prefix}
)
