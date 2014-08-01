execute "ldconfig" do
  command "ldconfig"
  action :nothing
end

if platform?("ubuntu", "centos")
  package "cmake"
  package "perl"
end

# gcc
if platform?("centos")
  remote_file "/etc/yum.repos.d/devtools-1.1.repo" do
    source "http://people.centos.org/tru/devtools-1.1/devtools-1.1.repo"
    checksum "1a34b17c10e93e715d99be3a842047fc6d3233a2f5cda0643bfaaaa380c16928"
    mode "0644"
    action :create_if_missing
  end

  execute "Installing g++-4.8" do
    cwd "/etc/yum.repos.d"
    command "yum -y --enablerepo=testing-1.1-devtools-6 install devtoolset-1.1-gcc devtoolset-1.1-gcc-c++"
    creates "/opt/centos/devtoolset-1.1/root/usr/bin/g++"
  end

  execute "install compilers" do
    command "cp /opt/centos/devtoolset-1.1/root/usr/bin/* /usr/local/bin"
    creates "/usr/local/bin/g++"
  end
elsif platform?("ubuntu")
  package "g++"
end

# zlib
if platform?("centos")
  package "zlib"
  package "zlib-devel"
elsif platform?("ubuntu")
  package "zlib1g-dev"
end

# bzip
if platform?("centos", "ubuntu")
  remote_file "#{Chef::Config[:file_cache_path]}/bzip2-#{node["bzip2"]["archive"]["version"]}.tar.gz" do
    source node["bzip2"]["archive"]["url"]
    checksum node["bzip2"]["archive"]["checksum"]
    mode "0644"
    action :create_if_missing
  end

  execute "Extracting bzip2 #{node["bzip2"]["archive"]["version"]}" do
    cwd Chef::Config[:file_cache_path]
    command "tar -zxf bzip2-#{node["bzip2"]["archive"]["version"]}.tar.gz"
    creates "#{Chef::Config[:file_cache_path]}/bzip2-#{node["bzip2"]["archive"]["version"]}"
  end

  execute "Installing bzip2 #{node["bzip2"]["archive"]["version"]} archive" do
    cwd "#{Chef::Config[:file_cache_path]}/bzip2-#{node["bzip2"]["archive"]["version"]}"
    command "make && make install"
    not_if { ::File.exists? "#{node["bzip2"]["archive"]["install_dir"]}/lib/libbz2.a" }
    env ({"PATH" => "/opt/chef/embedded/bin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin"})
    action :run
    notifies :run, "execute[ldconfig]", :immediately
  end
end

# gflags
if platform?("centos", "ubuntu")
  remote_file "#{Chef::Config[:file_cache_path]}/gflags-#{node["gflags"]["archive"]["version"]}.tar.gz" do
    source node["gflags"]["archive"]["url"]
    checksum node["gflags"]["archive"]["checksum"]
    mode "0644"
    action :create_if_missing
  end

  execute "Extracting gflags #{node["gflags"]["archive"]["version"]}" do
    cwd Chef::Config[:file_cache_path]
    command "tar -zxf gflags-#{node["gflags"]["archive"]["version"]}.tar.gz"
    creates "#{Chef::Config[:file_cache_path]}/gflags-#{node["gflags"]["archive"]["version"]}"
  end

  execute "Installing gflags #{node["gflags"]["archive"]["version"]} archive" do
    cwd "#{Chef::Config[:file_cache_path]}/gflags-#{node["gflags"]["archive"]["version"]}"
    command "./configure --prefix=#{node["gflags"]["archive"]["install_dir"]} && make && make check && make install"
    not_if { ::File.exists? "#{node["gflags"]["archive"]["install_dir"]}/lib/libgflags.a" }
    action :run
    notifies :run, "execute[ldconfig]", :immediately
  end
end

# glog
if platform?("centos", "ubuntu")
  remote_file "#{Chef::Config[:file_cache_path]}/glog-#{node["glog"]["archive"]["version"]}.tar.gz" do
    source node["glog"]["archive"]["url"]
    checksum node["glog"]["archive"]["checksum"]
    mode "0644"
    action :create_if_missing
  end

  execute "Extracting glog #{node["glog"]["archive"]["version"]}" do
    cwd Chef::Config[:file_cache_path]
    command "tar -zxf glog-#{node["glog"]["archive"]["version"]}.tar.gz"
    creates "#{Chef::Config[:file_cache_path]}/glog-#{node["glog"]["archive"]["version"]}"
  end

  execute "Installing glog #{node["glog"]["archive"]["version"]} archive" do
    cwd "#{Chef::Config[:file_cache_path]}/glog-#{node["glog"]["archive"]["version"]}"
    command "./configure --prefix=#{node["glog"]["archive"]["install_dir"]} && make && make check && make install"
    not_if { ::File.exists? "#{node["glog"]["archive"]["install_dir"]}/lib/libglog.a" }
    action :run
    notifies :run, "execute[ldconfig]", :immediately
  end
end

# gtest
if platform?("centos", "ubuntu")
  package "unzip"

  remote_file "#{Chef::Config[:file_cache_path]}/gtest-1.7.0.zip" do
    source "https://googletest.googlecode.com/files/gtest-1.7.0.zip"
    action :create_if_missing
  end

  execute "unzip gtest" do
    cwd "#{Chef::Config[:file_cache_path]}"
    command "unzip gtest-1.7.0.zip"
    creates "#{Chef::Config[:file_cache_path]}/gtest-1.7.0"
  end

  script "install gtest" do
    interpreter "sh"
    cwd "#{Chef::Config[:file_cache_path]}/gtest-1.7.0"
    code <<-EOS
    ./configure
    make
    cp -r include/gtest /usr/local/include
    cp lib/.libs/* /usr/local/lib
    EOS
    creates "/usr/local/include/gtest/gtest.h"
  end
end

# snappy
if platform?("centos", "ubuntu")
  remote_file "#{Chef::Config[:file_cache_path]}/snappy-#{node["snappy"]["archive"]["version"]}.tar.gz" do
    source node["snappy"]["archive"]["url"]
    checksum node["snappy"]["archive"]["checksum"]
    mode "0644"
    action :create_if_missing
  end

  execute "Extracting snappy #{node["snappy"]["archive"]["version"]}" do
    cwd Chef::Config[:file_cache_path]
    command "tar -zxf snappy-#{node["snappy"]["archive"]["version"]}.tar.gz"
    creates "#{Chef::Config[:file_cache_path]}/snappy-#{node["snappy"]["archive"]["version"]}"
  end

  execute "Installing snappy #{node["snappy"]["archive"]["version"]} archive" do
    cwd "#{Chef::Config[:file_cache_path]}/snappy-#{node["snappy"]["archive"]["version"]}"
    command "./configure --prefix=#{node["snappy"]["archive"]["install_dir"]} && make && make check && make install"
    not_if { ::File.exists? "#{node["snappy"]["archive"]["install_dir"]}/lib/libsnappy.a" }
    action :run
    notifies :run, "execute[ldconfig]", :immediately
  end
end

# rocksdb
if platform?("ubuntu", "centos")
  remote_file "#{Chef::Config[:file_cache_path]}/rocksdb-#{node["rocksdb"]["archive"]["version"]}.tar.gz" do
    source node["rocksdb"]["archive"]["url"]
    checksum node["rocksdb"]["archive"]["checksum"]
    mode "0644"
    action :create_if_missing
  end

  execute "Extracting rocksdb #{node["rocksdb"]["archive"]["version"]}" do
    cwd Chef::Config[:file_cache_path]
    command "tar -zxf rocksdb-#{node["rocksdb"]["archive"]["version"]}.tar.gz"
    creates "#{Chef::Config[:file_cache_path]}/rocksdb-rocksdb-#{node["rocksdb"]["archive"]["version"]}"
  end

  rocksdb_lib_path = "#{node["rocksdb"]["archive"]["install_dir"]}/lib/librocksdb.a"
  rocksdb_inc_path = "#{node["rocksdb"]["archive"]["install_dir"]}/include"

  execute "Installing rocksdb #{node["rocksdb"]["archive"]["version"]} archive" do
    cwd "#{Chef::Config[:file_cache_path]}/rocksdb-rocksdb-#{node["rocksdb"]["archive"]["version"]}"
    command "make static_lib && cp librocksdb.a #{rocksdb_lib_path} && cp -r include/rocksdb #{rocksdb_inc_path}"
    not_if { ::File.exists? "#{node["rocksdb"]["archive"]["install_dir"]}/lib/librocksdb.a" }
    action :run
    notifies :run, "execute[ldconfig]", :immediately
  end
end

# python
if platform?("centos")
  package "python-devel"
elsif platform?("ubuntu")
  package "python-dev"
end

# boost
if platform?("ubuntu", "centos")
  remote_file "#{Chef::Config[:file_cache_path]}/boost_#{node["boost"]["archive"]["version"]}.tar.gz" do
    source node["boost"]["archive"]["url"]
    checksum node["boost"]["archive"]["checksum"]
    mode "0644"
    action :create_if_missing
  end

  execute "Extracting boost #{node["boost"]["archive"]["version"]}" do
    cwd Chef::Config[:file_cache_path]
    command "tar -xvzf boost_#{node["boost"]["archive"]["version"]}.tar.gz"
    creates "#{Chef::Config[:file_cache_path]}/boost-#{node["boost"]["archive"]["version"]}"
  end

  log "Building boost #{node["boost"]["archive"]["version"]}"
  execute "Building boost #{node["boost"]["archive"]["version"]}" do
    cwd "#{Chef::Config[:file_cache_path]}/boost_#{node["boost"]["archive"]["version"]}"
    command "./bootstrap.sh && ./b2 install"
    not_if { ::File.exists? "/usr/local/lib/libboost_filesystem.a" }
    action :run
    notifies :run, "execute[ldconfig]", :immediately
  end
end


