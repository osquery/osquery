require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Zzuf < AbstractOsqueryFormula
  desc "Transparent application input fuzzer"
  homepage "http://caca.zoy.org/wiki/zzuf"
  url "https://github.com/theopolis/zzuf/archive/v0.15-osx-r2.tar.gz"
  sha256 "9f59bac21aef5408bbdaab0b2732ca5848dbd3e74297b66c34245bdbc04db86e"
  version "0.15-osx-r2"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "da9a3da97e8d2f884dddaa9e9dd219d43459850f88a283bfe78b5a8bb7b33655" => :sierra
    sha256 "e3bf2204807277382cf513cfb9f640278071098e12cd64952686f564d0f0dbf4" => :x86_64_linux
  end

  head do
    url "https://github.com/samhocevar/zzuf.git"

    depends_on "autoconf"   => :build
    depends_on "automake"   => :build
    depends_on "libtool"    => :build
    depends_on "pkg-config" => :build
  end

  def install
    system "./bootstrap"
    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}"
    system "make", "install"
  end

  test do
    output = pipe_output("#{bin}/zzuf -i -B 4194304 -r 0.271828 -s 314159 -m < /dev/zero").chomp
    assert_equal "zzuf[s=314159,r=0.271828]: 549e1200590e9c013e907039fe535f41", output
  end
end
