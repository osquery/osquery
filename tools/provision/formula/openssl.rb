require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Openssl < AbstractOsqueryFormula
  desc "SSL/TLS cryptography library"
  homepage "https://openssl.org/"
  license "OpenSSL"
  url "https://www.openssl.org/source/openssl-1.0.2m.tar.gz"
  mirror "https://dl.bintray.com/homebrew/mirror/openssl-1.0.2m.tar.gz"
  mirror "https://www.mirrorservice.org/sites/ftp.openssl.org/source/openssl-1.0.2m.tar.gz"
  sha256 "8c6ff15ec6b319b50788f42c7abc2890c08ba5a1cdcd3810eb9092deada37b0f"
  revision 102

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "023a6f557c41015694c6508142687af7979d864f71a70b038b0aaafb945bc714" => :sierra
    sha256 "79f095df9b09ea7b49165e2cc37e1ddd087365623d3186e499b70c30e6fcb25a" => :x86_64_linux
  end

  resource "cacert" do
    # Update post_install when you update this resource.
    # homepage "http://curl.haxx.se/docs/caextract.html"
    url "https://curl.haxx.se/ca/cacert-2017-09-20.pem"
    sha256 "435ac8e816f5c10eaaf228d618445811c16a5e842e461cb087642b6265a36856"
  end

  option "without-test", "Skip build-time tests (not recommended)"

  deprecated_option "without-check" => "without-test"

  depends_on "makedepend" => :build
  depends_on "zlib" unless OS.mac?
  depends_on :perl => ["5.0", :build] unless OS.mac?

  def arch_args
    if OS.linux?
      %w[linux-x86_64]
    else
      %w[darwin64-x86_64-cc enable-ec_nistp_64_gcc_128]
    end
  end

  def configure_args
    args = [
      "--prefix=#{prefix}",
      "--openssldir=#{openssldir}",
      "no-ssl2",
      "no-ssl3",
      "no-asm",
      "no-shared",
      "no-weak-ssl-ciphers",
      "zlib-dynamic",
      "enable-cms",
    ]
    if OS.linux?
      args += [
        ENV.cppflags,
        ENV.cflags,
        ENV.ldflags,
      ]
    end
    return args
  end

  def install
    # Load zlib from an explicit path instead of relying on dyld's fallback
    # path, which is empty in a SIP context. This patch will be unnecessary
    # when we begin building openssl with no-comp to disable TLS compression.
    # https://langui.sh/2015/11/27/sip-and-dlopen
    inreplace "crypto/comp/c_zlib.c",
              'zlib_dso = DSO_load(NULL, "z", NULL, 0);',
              'zlib_dso = DSO_load(NULL, "/usr/lib/libz.dylib", NULL, DSO_FLAG_NO_NAME_TRANSLATION);' if OS.mac?

    ENV.deparallelize
    system "perl", "./Configure", *(configure_args + arch_args)
    system "make", "depend"
    system "make"
    system "make", "test" if build.with?("test")
    system "make", "install", "MANDIR=#{man}", "MANSUFFIX=ssl"
  end

  def openssldir
    etc/"openssl"
  end

  def post_install
    ENV.delete "LIBRARY_PATH"
    (etc/"openssl").install resource("cacert").files("cacert-2017-09-20.pem" => "cert.pem")
  end

  def caveats; <<-EOS.undent
    A CA file has been bootstrapped using certificates from the system
    keychain. To add additional certificates, place .pem files in
      #{openssldir}/certs

    and run
      #{opt_bin}/c_rehash
    EOS
  end

  test do
    # Make sure the necessary .cnf file exists, otherwise OpenSSL gets moody.
    assert (HOMEBREW_PREFIX/"etc/openssl/openssl.cnf").exist?,
            "OpenSSL requires the .cnf file for some functionality"

    # Check OpenSSL itself functions as expected.
    (testpath/"testfile.txt").write("This is a test file")
    expected_checksum = "e2d0fe1585a63ec6009c8016ff8dda8b17719a637405a4e23c0ff81339148249"
    system "#{bin}/openssl", "dgst", "-sha256", "-out", "checksum.txt", "testfile.txt"
    open("checksum.txt") do |f|
      checksum = f.read(100).split("=").last.strip
      assert_equal checksum, expected_checksum
    end
  end
end
