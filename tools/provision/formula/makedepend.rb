require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Makedepend < AbstractOsqueryFormula
  desc "Creates dependencies in makefiles"
  homepage "https://x.org/"
  url "https://xorg.freedesktop.org/releases/individual/util/makedepend-1.0.5.tar.bz2"
  mirror "http://xorg.mirrors.pair.com/individual/util/makedepend-1.0.5.tar.bz2"
  sha256 "f7a80575f3724ac3d9b19eaeab802892ece7e4b0061dd6425b4b789353e25425"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    rebuild 1
    sha256 "648d18f27ef8ea0067a1d315ac9ffedece1734d950fa1228175ddd6f04c02ecf" => :high_sierra
  end

  depends_on "pkg-config" => :build

  def install
    ENV.append_path "PKG_CONFIG_PATH", "#{buildpath}/xproto/lib/pkgconfig"
    ENV.append_path "PKG_CONFIG_PATH", "#{buildpath}/xorg-macros/share/pkgconfig"

    system "./configure", "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}"
    system "make", "install"
  end

  test do
    touch "Makefile"
    system "#{bin}/makedepend"
  end
end
