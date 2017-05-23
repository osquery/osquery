require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libmagic < AbstractOsqueryFormula
  desc "Implementation of the file(1) command"
  homepage "https://www.darwinsys.com/file/"
  url "https://fossies.org/linux/misc/file-5.29.tar.gz"
  sha256 "ea661277cd39bf8f063d3a83ee875432cc3680494169f952787e002bdd3884c0"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "9f8ab6e8dd6959cdaacf06c08e25dcc4991a90cdba2616c7c83470411c11c381" => :sierra
    sha256 "9fef726c4275e2d1910a6ef534edd51f2cfc0b9b1c7a14784c6e3c9f8690a5dc" => :x86_64_linux
  end

  depends_on :python => :optional

  option :universal

  def install
    ENV.universal_binary if build.universal?

    system "./configure", "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}",
                          "--enable-fsect-man5",
                          "--enable-static"
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
