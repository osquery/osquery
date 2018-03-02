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
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "f472ad6242a1e6ed6ec8bede925096226d471ad3cb79529917f9ff0c15705186" => :x86_64_linux
  end

  option :universal

  def install
    ENV.universal_binary if build.universal?
    system "./configure", "--disable-debug",
                          "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}",
                          "--disable-shared",
                          "--enable-static"
    system "make", "install"
  end

  test do
    path = testpath/"data.txt"
    original_contents = "." * 1000
    path.write original_contents

    # compress: data.txt -> data.txt.xz
    system bin/"xz", path
    assert !path.exist?

    # decompress: data.txt.xz -> data.txt
    system bin/"xz", "-d", "#{path}.xz"
    assert_equal original_contents, path.read
  end
end
