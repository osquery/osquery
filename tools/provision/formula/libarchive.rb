require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libarchive < AbstractOsqueryFormula
  desc "Multi-format archive and compression library"
  homepage "http://www.libarchive.org"
  url "http://www.libarchive.org/downloads/libarchive-3.2.2.tar.gz"
  sha256 "691c194ee132d1f0f7a42541f091db811bc2e56f7107e9121be2bc8c04f1060f"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "dc82cff7fdb4932a2025efe6ee914d2a20e63e41ce44831cb0a413e3ab4c9818" => :sierra
    sha256 "e8fcc61d81feeca6b63ece2e61e5d4bf812c183265bcf3918eaf10216f608e52" => :x86_64_linux
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
