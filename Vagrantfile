Vagrant.configure("2") do |config|

  config.vm.provider "virtualbox" do |v|
    v.memory = 4096
    v.cpus = 2
  end
 [
   %w{centos6.5 chef/centos-6.5},
   %w{centos7   chef/centos-7},
   %w{ubuntu14  ubuntu/trusty64},
   %w{ubuntu12  ubuntu/precise64},
   %w{freebsd10 chef/freebsd-10.0}
 ].each do |machine|
  (name, box) = machine
  config.vm.define name do |build|
    # Private network for NFS
    build.vm.box = box
    build.vm.network :private_network, ip: "192.168.56.101"

    # configure the NICs
    build.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
      vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
    end

    build.vm.synced_folder ".", "/vagrant", type: "nfs"

    build.vm.provision "shell",
      inline: "pkg install -y gmake"
    end
  end
end
