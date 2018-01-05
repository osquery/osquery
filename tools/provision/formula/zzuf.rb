require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Zzuf < AbstractOsqueryFormula
  desc "Transparent application input fuzzer"
  homepage "http://caca.zoy.org/wiki/zzuf"
  url "https://github.com/theopolis/zzuf/archive/v0.15-osx-r2.tar.gz"
  sha256 "9f59bac21aef5408bbdaab0b2732ca5848dbd3e74297b66c34245bdbc04db86e"
  head "https://github.com/samhocevar/zzuf.git"
  version "0.15-osx-r2"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "8641ceb33aff772847483491064fd02c779d374442a11c668b9a1880dd9017f4" => :sierra
    sha256 "8b7b3437c5dd30fa2d41bcb46d2ec3970efb38a7c26a5eadef0e9eda4e9869a3" => :x86_64_linux
  end

  def install
    system "./bootstrap"
    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}"
    system "make", "install"
  end
end
