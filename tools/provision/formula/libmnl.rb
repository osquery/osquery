require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libmnl < AbstractOsqueryFormula
  desc "Minimalistic user-space library oriented to Netlink developers"
  homepage "http://www.netfilter.org/projects/libmnl/"
  url "http://www.netfilter.org/projects/libmnl/files/libmnl-1.0.4.tar.bz2"
  sha256 "171f89699f286a5854b72b91d06e8f8e3683064c5901fb09d954a9ab6f551f81"
  version "1.0.4"

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
