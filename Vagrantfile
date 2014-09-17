Vagrant.configure("2") do |config|

  config.vm.provider "virtualbox" do |v|
    v.memory = 8192
    v.cpus = 4
  end

  config.vm.define "ubuntu" do |box|
    box.vm.box = "ubuntu/trusty64"
  end

  config.vm.define "centos" do |box|
    box.vm.box = "chef/centos-6.5"
  end

end
