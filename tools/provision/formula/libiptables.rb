require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libiptables < AbstractOsqueryFormula
  desc "Device Mapper development"
  homepage "http://netfilter.samba.org/"
  license "GPL-2.0+"
  url "https://www.netfilter.org/projects/iptables/files/iptables-1.8.0.tar.bz2"
  sha256 "c4cbfa187c4296e4bc2e347ebbc21e309def7274773f20f0df0b8feaf7e8de50"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b3d67a93150bd442e3f4b46841c693e23f2cf189c3f5f9990a29522c574993fa" => :x86_64_linux
  end

  def install
    args = [
      "--disable-shared",
    ]

    system "./configure", "--prefix=#{prefix}", *args
    cd "libiptc" do
      system "make", "install"
    end
    cd "include" do
      system "make", "install"
		end
  end
end
