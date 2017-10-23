require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libdevmapper < AbstractOsqueryFormula
  desc "Device Mapper development"
  homepage "https://www.sourceware.org/dm/"
  url "https://www.mirrorservice.org/sites/sourceware.org/pub/lvm2/old/LVM2.2.02.173.tgz"
  sha256 "ceb9168c7e009ef487f96a1fe969b23cbb07d920ffb71769affdbdf30fea8d64"
  revision 2

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "2ea48fa7fc28b923c1f626b6eab2175953931d2a6f2b8363a5a67ecb3948969a" => :x86_64_linux
  end

  def install
    # When building with LLVM/clang do not expect symbol versioning information.
    inreplace "lib/misc/lib.h", "defined(__GNUC__)", "defined(__GNUC__) && !defined(__clang__)"

    args = [
      "--with-lvm1=none",
      "--disable-selinux",
      "--disable-shared",
      "--disable-readline",
      "--enable-static_link",
    ]

    system "./configure", "--prefix=#{prefix}", *args
    system "make", "libdm.device-mapper"

    cd "libdm" do
      system "make", "install"
    end

    cd "lib" do
      system "make"
    end

    cd "libdaemon" do
      system "make"
    end

    cd "liblvm" do
      system "make", "install"
    end

    # Install the internal methods needed by liblvm2app.
    system "cp", "lib/liblvm-internal.a", "#{prefix}/lib/"
    system "cp", "libdaemon/client/libdaemonclient.a", "#{prefix}/lib/"

    # Configure still installs the shared object library.
    rm_rf lib/"libdevmapper.so"
    rm_rf lib/"liblvm2app.so"
  end
end
