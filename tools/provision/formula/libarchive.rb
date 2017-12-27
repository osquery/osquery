require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libarchive < AbstractOsqueryFormula
  desc "Multi-format archive and compression library"
  homepage "http://www.libarchive.org"
  license "BSD-2-Clause"
  url "http://www.libarchive.org/downloads/libarchive-3.3.2.tar.gz"
  sha256 "ed2dbd6954792b2c054ccf8ec4b330a54b85904a80cef477a1c74643ddafa0ce"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "0dee0d31e321e1046b4c1d996ed9130a0422818f51521bf8a742b5d805ec3e86" => :sierra
    sha256 "8a64333cdb781499c3ae6596a902eb1df9dc74456ad68b6f5bfc3be357685e97" => :x86_64_linux
  end

  def install
    system "./configure",
           "--prefix=#{prefix}",
           "--without-lzo2",    # Use lzop binary instead of lzo2 due to GPL
           "--without-nettle",  # xar hashing option but GPLv3
           "--without-xml2",    # xar hashing option but tricky dependencies
           "--without-openssl", # mtree hashing now possible without OpenSSL
           "--with-expat",       # best xar hashing option
           "--disable-shared",
           "--enable-static"

    system "make", "install"

  end
end
