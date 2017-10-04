require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libcryptsetup < AbstractOsqueryFormula
  desc "Open source disk encryption libraries"
  homepage "https://gitlab.com/cryptsetup/cryptsetup"
  url "https://gitlab.com/cryptsetup/cryptsetup/repository/v1_7_5/archive.tar.gz"
  sha256 "6dead2f1420ab1c84a7e82f0ee197861f4a52e4c3284a0bfef824a90c392e077"
  version "1.7.5"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "c8d9ab1d4dd42b4046edd8e111f46cc9ce72498a1d2a41f2d052696eb3551a80" => :x86_64_linux
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
