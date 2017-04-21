require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libarchive < AbstractOsqueryFormula
  desc "Multi-format archive and compression library"
  homepage "http://www.libarchive.org"
  url "http://www.libarchive.org/downloads/libarchive-3.2.2.tar.gz"
  sha256 "691c194ee132d1f0f7a42541f091db811bc2e56f7107e9121be2bc8c04f1060f"
  revision 1

  bottle do
    cellar :any_skip_relocation
    sha256 "d7da800fa873e8f7534649b159643b362d118324fb96151732ec30777857863b" => :sierra
    sha256 "4f1b4e3baf0e5303a6cf0f4a179b63ca1774e2306617f63243d018c35441a51e" => :x86_64_linux
  end

  depends_on "xz" => :recommended
  depends_on "lz4" => :optional
  depends_on "lzop" => :optional

  def install
    system "./configure",
           "--prefix=#{prefix}",
           "--without-lzo2",    # Use lzop binary instead of lzo2 due to GPL
           "--without-nettle",  # xar hashing option but GPLv3
           "--without-xml2",    # xar hashing option but tricky dependencies
           "--without-openssl", # mtree hashing now possible without OpenSSL
           "--with-expat"       # best xar hashing option

    system "make", "install"

  end

  test do
    (testpath/"test").write("test")
    system bin/"bsdtar", "-czvf", "test.tar.gz", "test"
    assert_match /test/, shell_output("#{bin}/bsdtar -xOzf test.tar.gz")
  end
end
