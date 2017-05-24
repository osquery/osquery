require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libarchive < AbstractOsqueryFormula
  desc "Multi-format archive and compression library"
  homepage "http://www.libarchive.org"
  url "http://www.libarchive.org/downloads/libarchive-3.2.2.tar.gz"
  sha256 "691c194ee132d1f0f7a42541f091db811bc2e56f7107e9121be2bc8c04f1060f"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "edda4760384ef9ef69af0681d5bba2b2f508fd5188720ce1acbf3fc9890c91e7" => :sierra
    sha256 "a608dc2be02fe57c7ca22cba2cfd5612cc7a80b32e87beb504830025d998ca8e" => :x86_64_linux
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
