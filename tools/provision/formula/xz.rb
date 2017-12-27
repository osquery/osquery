require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

# Upstream project has requested we use a mirror as the main URL
# https://github.com/Homebrew/homebrew/pull/21419
class Xz < AbstractOsqueryFormula
  desc "General-purpose data compression with high compression ratio"
  homepage "http://tukaani.org/xz/"
  license "Public"
  url "https://fossies.org/linux/misc/xz-5.2.2.tar.gz"
  mirror "http://tukaani.org/xz/xz-5.2.2.tar.gz"
  sha256 "73df4d5d34f0468bd57d09f2d8af363e95ed6cc3a4a86129d2f2c366259902a2"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "7dd32d61f232f05359ceb52ccb0594c64c1c6d6a8f2532b4627625f4567026d6" => :x86_64_linux
  end

  def install
    system "./configure", "--disable-debug",
                          "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}",
                          "--disable-shared",
                          "--enable-static"
    system "make", "install"
  end
end
