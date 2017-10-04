require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libmagic < AbstractOsqueryFormula
  desc "Implementation of the file(1) command"
  homepage "https://www.darwinsys.com/file/"
  url "https://distfiles.macports.org/file/file-5.32.tar.gz"
  sha256 "8639dc4d1b21e232285cd483604afc4a6ee810710e00e579dbe9591681722b50"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "6f472165a18ab7c5587eeb3646db16c7a6659cb8ce27b57fb99cd6d64d8aaee8" => :sierra
    sha256 "3778b2485218af6402419314b6702f355b8a0499586bc7d544bca993a408e02e" => :x86_64_linux
  end

  depends_on :python => :optional

  option :universal

  def install
    ENV.universal_binary if build.universal?

    system "./configure", "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}",
                          "--enable-fsect-man5",
                          "--enable-static",
                          "--disable-shared"
    system "make", "install"
    (share+"misc/magic").install Dir["magic/Magdir/*"]

    if build.with? "python"
      cd "python" do
        system "python", *Language::Python.setup_install_args(prefix)
      end
    end

    # Don't dupe this system utility
    rm bin/"file"
    rm man1/"file.1"
  end
end
