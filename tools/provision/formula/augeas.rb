require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Augeas < AbstractOsqueryFormula
  desc "A configuration editing tool and API"
  homepage "http://augeas.net/"
  url "https://github.com/hercules-team/augeas.git",
    :revision => "c765202fb507fa882ce7b5706265e040c65aa3bf"
  version "1.7.0rc1"
  revision 1

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "8ef71ee4d9bb8c976150af61e811ff31e065ffb9f6c28cc4b8b8cd7145e9cd2c" => :x86_64_linux
  end

  def install
    ENV.append_to_cflags "-I/usr/include/libxml2" if OS.mac?
    system "./autogen.sh", "--without-selinux", "--prefix=#{prefix}"

    # Build the local gnulib checkout.
    cd "gnulib/lib" do
      system "make"
    end

    # Skip building augtool and augparse to avoid readline requirements.
    cd "src" do
      system "make", "datadir.h"
      system "make", "install-libLTLIBRARIES"
      system "make", "install-data-am"
    end

    # Install the lenses on the build machine.
    system "make", "install-data-am"
  end
end
