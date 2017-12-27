require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libcryptsetup < AbstractOsqueryFormula
  desc "Open source disk encryption libraries"
  homepage "https://gitlab.com/cryptsetup/cryptsetup"
  license "LGPL-2.1+"
  url "https://gitlab.com/cryptsetup/cryptsetup/repository/v1_7_5/archive.tar.gz"
  sha256 "6dead2f1420ab1c84a7e82f0ee197861f4a52e4c3284a0bfef824a90c392e077"
  version "1.7.5"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "dc1d7be5f2518743f0c83a7a7f163a3893f3620f88a615698b5f942286037b43" => :x86_64_linux
  end

  def install
    ENV.append "LDFLAGS", "-lm"

    args = [
      "--disable-selinux",
      "--disable-udev",
      "--disable-veritysetup",
      "--disable-nls",
      "--disable-kernel_crypto",
      "--enable-static",
      "--disable-shared",
    ]

    system "./autogen.sh", "--prefix=#{prefix}", *args
    cd "lib" do
      system "make"
      system "make", "install"
    end
  end
end
