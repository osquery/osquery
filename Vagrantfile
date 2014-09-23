Vagrant.configure("2") do |config|

  config.vm.provider "virtualbox" do |v|
    v.memory = 4096
    v.cpus = 2
  end

  config.vm.define "ubuntu14" do |box|
    box.vm.box = "ubuntu/trusty64"
  end

  config.vm.define "ubuntu12" do |box|
    box.vm.box = "ubuntu/precise64"
  end

  config.vm.define "centos" do |box|
    box.vm.box = "chef/centos-6.5"
  end

end
