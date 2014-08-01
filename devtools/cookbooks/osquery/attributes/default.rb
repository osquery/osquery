default["boost"]["archive"]["version"] = "1_55_0"
default["boost"]["archive"]["version_mod"] = "1.55.0"
default["boost"]["archive"]["url"] = "http://sourceforge.net/projects/boost/files/boost/#{node["boost"]["archive"]["version_mod"]}/boost_#{node["boost"]["archive"]["version"]}.tar.gz/download"
default["boost"]["archive"]["url"] = "http://downloads.sourceforge.net/project/boost/boost/#{node["boost"]["archive"]["version_mod"]}/boost_#{node["boost"]["archive"]["version"]}.tar.gz"
default["boost"]["archive"]["checksum"] =
  case node["boost"]["archive"]["version"]
    when "1_55_0" then "19c4305cd6669f2216260258802a7abc73c1624758294b2cad209d45cc13a767"
  end

default["bzip2"]["archive"]["install_dir"] = "/usr/local"
default["bzip2"]["archive"]["version"] = "1.0.6"
default["bzip2"]["archive"]["url"] = "http://www.bzip.org/#{node["bzip2"]["archive"]["version"]}/bzip2-#{node["bzip2"]["archive"]["version"]}.tar.gz"
default["bzip2"]["archive"]["checksum"] =
  case node["bzip2"]["archive"]["version"]
    when "2.0" then "a2848f34fcd5d6cf47def00461fcb528a0484d8edef8208d6d2e2909dc61d9cd"
  end

default["gflags"]["archive"]["install_dir"] = "/usr/local"
default["gflags"]["archive"]["version"] = "2.0"
default["gflags"]["archive"]["url"] = "https://gflags.googlecode.com/files/gflags-#{node["gflags"]["archive"]["version"]}.tar.gz"
default["gflags"]["archive"]["checksum"] =
  case node["gflags"]["archive"]["version"]
    when "2.0" then "ce4a5d3419f27a080bd68966e5cd9507bfa09d14341e07b78a1778a7a172d7d7"
  end

default["snappy"]["archive"]["install_dir"] = "/usr/local"
default["snappy"]["archive"]["version"] = "1.1.1"
default["snappy"]["archive"]["url"] = "https://snappy.googlecode.com/files/snappy-#{node["snappy"]["archive"]["version"]}.tar.gz"
default["snappy"]["archive"]["checksum"] =
  case node["snappy"]["archive"]["version"]
    when "1.1.1" then "d79f04a41b0b513a014042a4365ec999a1ad5575e10d5e5578720010cb62fab3"
  end

default["glog"]["archive"]["install_dir"] = "/usr/local"
default["glog"]["archive"]["version"] = "0.3.3"
default["glog"]["archive"]["url"] = "https://google-glog.googlecode.com/files/glog-#{node["glog"]["archive"]["version"]}.tar.gz"
default["glog"]["archive"]["checksum"] =
  case node["snappy"]["archive"]["version"]
    when "0.3.3" then "fbf90c2285ba0561db7a40f8a4eefb9aa963e7d399bd450363e959929fe849d0"
  end

default["rocksdb"]["archive"]["install_dir"] = "/usr/local"
default["rocksdb"]["archive"]["version"] = "3.2"
default["rocksdb"]["archive"]["url"] = "https://github.com/facebook/rocksdb/archive/rocksdb-#{node["rocksdb"]["archive"]["version"]}.tar.gz"
default["rocksdb"]["archive"]["checksum"] =
  case node["rocksdb"]["archive"]["version"]
    when "0.3.3" then "e36aed1d9f4185714d876413505f19685344ecb1ff65fc1f34f308985cb8f0bc"
  end
