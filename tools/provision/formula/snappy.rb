require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Snappy < AbstractOsqueryFormula
  desc "Compression/decompression library aiming for high speed"
  homepage "https://code.google.com/p/snappy/"
  url "https://github.com/google/snappy/releases/download/1.1.3/snappy-1.1.3.tar.gz"
  sha256 "2f1e82adf0868c9e26a5a7a3115111b6da7e432ddbac268a7ca2fae2a247eef3"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "ab880558e095b6015b86bba48b78c0c937f8a906fcb6e13df0a2875d0aaee82e" => :sierra
    sha256 "556e3a859d8820966af0964aa974ef7c10aafa2d68c06ba8b33039560bb92c88" => :x86_64_linux
  end

  head do
    url "https://github.com/google/snappy.git"
    depends_on "automake" => :build
    depends_on "autoconf" => :build
    depends_on "libtool" => :build
  end

  option :universal

  depends_on "pkg-config" => :build

  def install
    ENV.universal_binary if build.universal?
    ENV.j1 if build.stable?

    system "./autogen.sh" if build.head?
    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}",
                          "--disable-shared",
                          "--enable-static"
    system "make", "install"
  end

  test do
    (testpath/"test.cpp").write <<-EOS.undent
      #include <assert.h>
      #include <snappy.h>
      #include <string>
      using namespace std;
      using namespace snappy;

      int main()
      {
        string source = "Hello World!";
        string compressed, decompressed;
        Compress(source.data(), source.size(), &compressed);
        Uncompress(compressed.data(), compressed.size(), &decompressed);
        assert(source == decompressed);
        return 0;
      }
    EOS

    system ENV.cxx, "test.cpp", "-L#{lib}", "-lsnappy", "-o", "test"
    system "./test"
  end
end
