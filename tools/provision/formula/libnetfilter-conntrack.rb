require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class LibnetfilterConntrack < AbstractOsqueryFormula
  desc "userspace library providing a programming interface (API) to the in-kernel connection tracking state table"
  homepage "http://www.netfilter.org/projects/libmnl/"
  url "http://netfilter.org/projects/libnetfilter_conntrack/files/libnetfilter_conntrack-1.0.6.tar.bz2"
  sha256 "efcc08021284e75f4d96d3581c5155a11f08fd63316b1938cbcb269c87f37feb"
  version "1.0.6"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
  end


  def install
    args = %W[
      --prefix=#{prefix}
      --enable-static
    ]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end
