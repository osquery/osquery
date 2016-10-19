require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Zzuf < AbstractOsqueryFormula
  desc "Transparent application input fuzzer"
  homepage "http://caca.zoy.org/wiki/zzuf"
  url "https://github.com/theopolis/zzuf/archive/v0.15-osx-r1.tar.gz"
  sha256 "78c2250829b205c94643afa31bf8155bac629c9c8676d9a37670c62c16f4f03b"
  version "0.15-osx-r1"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "0811de4fdac7e4188c61fea1318c759fffe334011c342f0f370f0942844054c1" => :sierra
    sha256 "37ef864273fa364fd08e26b5173c12e70ab9d6d42b988b4b2f36a8835c156d42" => :el_capitan
    sha256 "6e2de1bed215d2c945b6283cb07a642124a954061086b3ea93eefdedacb8a7a1" => :x86_64_linux
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
