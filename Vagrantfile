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

  config.vm.define "freebsd10.0" do |box|
    box.vm.box = "chef/freebsd-10.0"

    # Private network for NFS
    box.vm.network :private_network, ip: "192.168.56.101"

    # configure the NICs
    box.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
      vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
    end

    box.vm.synced_folder ".", "/vagrant", type: "nfs"
  end

end
