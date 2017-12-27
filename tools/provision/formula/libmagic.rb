require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libmagic < AbstractOsqueryFormula
  desc "Implementation of the file(1) command"
  homepage "https://www.darwinsys.com/file/"
  license "BSD-2-Clause"
  url "https://distfiles.macports.org/file/file-5.32.tar.gz"
  sha256 "8639dc4d1b21e232285cd483604afc4a6ee810710e00e579dbe9591681722b50"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "aded14705f5ef4cce9b62b4be7157c63ebebed871f8f2e20bf2f23423c56eb4f" => :sierra
    sha256 "b92728f8418492c61283600befdabbb891eba150d0611f10a4bc53989825952a" => :x86_64_linux
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
