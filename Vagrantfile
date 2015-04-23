Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |v|
    if ENV['OSQUERY_BUILD_CPUS']
      v.cpus = ENV['OSQUERY_BUILD_CPUS'].to_i
    else
      v.cpus = 2
    end
    v.memory = 4096
  end
 [
   %w{centos6.5 chef/centos-6.5},
   %w{centos7   chef/centos-7.0},
   %w{ubuntu14  ubuntu/trusty64},
   %w{ubuntu12  ubuntu/precise64},
   %w{freebsd10 chef/freebsd-10.0}
 ].each do |machine|
  (name, box) = machine
  config.vm.define name do |build|

    build.vm.box = box

    if name == 'freebsd10'
      # configure the NICs
      build.vm.provider :virtualbox do |vb|
        vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
        vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
      end
      # Private network for NFS
      build.vm.network :private_network, ip: "192.168.56.101"
      build.vm.synced_folder ".", "/vagrant", type: "nfs"
      build.vm.provision "shell",
        inline: "pkg install -y gmake"
      end
    end

  end
end
