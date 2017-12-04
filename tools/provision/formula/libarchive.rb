require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libarchive < AbstractOsqueryFormula
  desc "Multi-format archive and compression library"
  homepage "http://www.libarchive.org"
  license "BSD-2-Clause"
  url "http://www.libarchive.org/downloads/libarchive-3.3.2.tar.gz"
  sha256 "ed2dbd6954792b2c054ccf8ec4b330a54b85904a80cef477a1c74643ddafa0ce"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "a7bb4138e422a513c76b43dea7dd06ae80c28712451cacd30edb1db9e33be7e6" => :sierra
    sha256 "ee089bdc10500dc71f2f0ce1571b34b78dd1d06f6bac912ca30b7e10d4083cc1" => :x86_64_linux
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
           "--with-expat",       # best xar hashing option
           "--disable-shared",
           "--enable-static"

    system "make", "install"

  end

  test do
    (testpath/"test").write("test")
    system bin/"bsdtar", "-czvf", "test.tar.gz", "test"
    assert_match /test/, shell_output("#{bin}/bsdtar -xOzf test.tar.gz")
  end
end
