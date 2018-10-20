require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libipset < AbstractOsqueryFormula
  desc "ipset development library"
  homepage "http://ipset.netfilter.org/"
  license "GPL-2.0+"
  url "http://ipset.netfilter.org/ipset-6.38.tar.bz2"
  sha256 "ceef625ba31fe0aaa422926c7231a819de0b07644c02c17ebdd3022a29e3e244"

  def install
    system "./autogen.sh"
    system "./configure", "--prefix=#{prefix}"
    system "make"
    #system "make", "modules"
    system "make", "install"
    #system "make", "modules_install"
  end
end
