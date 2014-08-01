include_recipe "osquery::dependencies"

directory "/vagrant/build"

build_dir = "/vagrant/build/#{node["platform"]}"
directory build_dir

execute "build osquery" do
  cwd build_dir
  command "cmake ../.. && make -j5"
  action :run
end
