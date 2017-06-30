require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libnfnetlink < AbstractOsqueryFormula
  desc "Low-level library for netfilter related kernel/userspace communication"
  homepage "http://www.netfilter.org/projects/libnfnetlink/"
  url "http://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-1.0.1.tar.bz2"
  sha256 "f270e19de9127642d2a11589ef2ec97ef90a649a74f56cf9a96306b04817b51a"
  version "1.0.1"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
  end


  def install
    args = %W[--prefix=#{prefix} --enable-static]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end
