require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Openssl < AbstractOsqueryFormula
  desc "SSL/TLS cryptography library"
  homepage "https://openssl.org/"
  license "OpenSSL"
  url "https://www.openssl.org/source/openssl-1.0.2o.tar.gz"
  mirror "https://dl.bintray.com/homebrew/mirror/openssl-1.0.2o.tar.gz"
  mirror "https://www.mirrorservice.org/sites/ftp.openssl.org/source/openssl-1.0.2o.tar.gz"
  sha256 "ec3f5c9714ba0fd45cb4e087301eb1336c317e0d20b575a125050470e8089e4d"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "3539d1d207a40185d72ddf5c006813f0e97b29f4b88e7283366de5d366d190bc" => :sierra
    sha256 "ab20de60c78614159b11b46affc91b5a1eae2be2df017473461bfddef6bd37bd" => :x86_64_linux
  end

  resource "cacert" do
    # Update post_install when you update this resource.
    # homepage "http://curl.haxx.se/docs/caextract.html"
    url "https://curl.haxx.se/ca/cacert-2018-03-07.pem"
    sha256 "79ea479e9f329de7075c40154c591b51eb056d458bc4dff76d9a4b9c6c4f6d0b"
  end

  depends_on "zlib" unless OS.mac?

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
        ENV.ldflags,
      ]
    end
    args << ENV.cflags
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
    system "make", "test"
    system "make", "install", "MANDIR=#{man}", "MANSUFFIX=ssl"
  end

  def openssldir
    etc/"openssl"
  end

  def post_install
    ENV.delete "LIBRARY_PATH"
    (etc/"openssl").install resource("cacert").files("cacert-2018-03-07.pem" => "cert.pem")
  end

  def caveats; <<~EOS
    A CA file has been bootstrapped using certificates from the system
    keychain. To add additional certificates, place .pem files in
      #{openssldir}/certs

    and run
      #{opt_bin}/c_rehash
    EOS
  end
end
