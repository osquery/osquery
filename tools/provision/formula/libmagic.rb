require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libmagic < AbstractOsqueryFormula
  desc "Implementation of the file(1) command"
  homepage "https://www.darwinsys.com/file/"
  license "BSD-2-Clause"
  url "https://distfiles.macports.org/file/file-5.32.tar.gz"
  sha256 "8639dc4d1b21e232285cd483604afc4a6ee810710e00e579dbe9591681722b50"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "9018d1df107b9e02f7c2bc09722f5db47e3f9fcd1f5e78ddf6fc93f4c6c56d14" => :sierra
    sha256 "fc93dc4fff2228058abbc7e6acb6de2c86af40338cf4c09bd2af46495f1f959f" => :x86_64_linux
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
