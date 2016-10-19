require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Snappy < AbstractOsqueryFormula
  desc "Compression/decompression library aiming for high speed"
  homepage "https://code.google.com/p/snappy/"
  url "https://github.com/google/snappy/releases/download/1.1.3/snappy-1.1.3.tar.gz"
  sha256 "2f1e82adf0868c9e26a5a7a3115111b6da7e432ddbac268a7ca2fae2a247eef3"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "dc1023c5e85eda474df62e735d68c97656efa92974b28531737c5cddba511316" => :sierra
    sha256 "bfb084be2ab8d6d302504b306be9dcc753be9543aecbc0f695b6908b32efb2ee" => :el_capitan
    sha256 "d376883230a45dc1cc7f58fdaa5e5b06b913b0b7dd38d1ab55513bcbff795c1b" => :x86_64_linux
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
                          "--prefix=#{prefix}"
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
