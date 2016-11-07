require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Openssl < AbstractOsqueryFormula
  desc "SSL/TLS cryptography library"
  homepage "https://openssl.org/"
  url "https://www.openssl.org/source/openssl-1.0.2j.tar.gz"
  mirror "https://dl.bintray.com/homebrew/mirror/openssl-1.0.2j.tar.gz"
  mirror "https://www.mirrorservice.org/sites/ftp.openssl.org/source/openssl-1.0.2j.tar.gz"
  sha256 "e7aff292be21c259c6af26469c7a9b3ba26e9abaaffd325e3dccc9785256c431"
  revision 1

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "3a593fed8efd77bf6ae3b9e5b16f7c0072b2f249dff9222344e6a6191f0c76cb" => :sierra
    sha256 "fd11d0d4e127128b81810e1aff2dd7a2e4e81b916fa23cedb6955ddc73dacdb6" => :el_capitan
    sha256 "11cc84110960f765d1ee91a14425c6f4b09734272cd6f14a09f85ff428fe183a" => :x86_64_linux
  end

  resource "cacert" do
    # Update post_install when you update this resource.
    # homepage "http://curl.haxx.se/docs/caextract.html"
    url "https://curl.haxx.se/ca/cacert-2016-04-20.pem"
    sha256 "2c6d4960579b0d4fd46c6cbf135545116e76f2dbb7490e24cf330f2565770362"
  end

  option "without-test", "Skip build-time tests (not recommended)"

  deprecated_option "without-check" => "without-test"

  depends_on "makedepend" => :build
  depends_on "zlib" unless OS.mac?
  depends_on :perl => ["5.0", :build] unless OS.mac?

  def arch_args
    return { :i386  => %w[linux-generic32], :x86_64 => %w[linux-x86_64] } if OS.linux?
    {
      :x86_64 => %w[darwin64-x86_64-cc enable-ec_nistp_64_gcc_128],
      :i386   => %w[darwin-i386-cc],
    }
  end

  def configure_args
    args = [
      "--prefix=#{prefix}",
      "--openssldir=#{openssldir}",
      "no-ssl2",
      "no-ssl3",
      "no-asm",
      "zlib-dynamic",
      "shared",
      "enable-cms",
    ]
    if OS.linux?
      args << [
        ENV.cppflags,
        ENV.cflags,
        ENV.ldflags,
        "-Wl,--version-script=#{prefix}/openssl.ld",
      ].join(" ")
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

    archs = [Hardware::CPU.arch_64_bit]

    dirs = []

    version_script = prefix/"openssl.ld"
    version_script.write <<-EOS.undent
      OPENSSL_1.0.1d {
        global:
          *;
      };
      OPENSSL_1.0.1 {
        global:
          *;
      };
      OPENSSL_1.0.0 {
        global:
          *;
      };
    EOS

    archs.each do |arch|
      if build.universal?
        dir = "build-#{arch}"
        dirs << dir
        mkdir dir
        mkdir "#{dir}/engines"
        system "make", "clean"
      end

      ENV.deparallelize
      system "perl", "./Configure", *(configure_args + arch_args[arch])
      system "make", "depend"
      system "make"
      system "make", "test" if build.with?("test")

      if build.universal?
        cp "include/openssl/opensslconf.h", dir
        cp Dir["*.?.?.?.dylib", "*.a", "apps/openssl"], dir
        cp Dir["engines/**/*.dylib"], "#{dir}/engines"
      end
    end

    system "make", "install", "MANDIR=#{man}", "MANSUFFIX=ssl"

    if build.universal?
      %w[libcrypto libssl].each do |libname|
        system "lipo", "-create", "#{dirs.first}/#{libname}.1.0.0.dylib",
                                  "#{dirs.last}/#{libname}.1.0.0.dylib",
                       "-output", "#{lib}/#{libname}.1.0.0.dylib"
        system "lipo", "-create", "#{dirs.first}/#{libname}.a",
                                  "#{dirs.last}/#{libname}.a",
                       "-output", "#{lib}/#{libname}.a"
      end

      Dir.glob("#{dirs.first}/engines/*.dylib") do |engine|
        libname = File.basename(engine)
        system "lipo", "-create", "#{dirs.first}/engines/#{libname}",
                                  "#{dirs.last}/engines/#{libname}",
                       "-output", "#{lib}/engines/#{libname}"
      end

      system "lipo", "-create", "#{dirs.first}/openssl",
                                "#{dirs.last}/openssl",
                     "-output", "#{bin}/openssl"

      confs = archs.map do |arch|
        <<-EOS.undent
          #ifdef __#{arch}__
          #{(buildpath/"build-#{arch}/opensslconf.h").read}
          #endif
          EOS
      end
      (include/"openssl/opensslconf.h").atomic_write confs.join("\n")
    end
  end

  def openssldir
    etc/"openssl"
  end

  def post_install
    ENV.delete "LIBRARY_PATH"
    unless OS.mac?
      # Optional: Download and install cacert.pem from curl.haxx.se
      (etc/"openssl").install resource("cacert").files("cacert-2016-04-20.pem" => "cert.pem")
      return
    end

    keychains = %w[
      /Library/Keychains/System.keychain
      /System/Library/Keychains/SystemRootCertificates.keychain
    ]

    certs_list = `security find-certificate -a -p #{keychains.join(" ")}`
    certs = certs_list.scan(
      /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m
    )

    valid_certs = certs.select do |cert|
      IO.popen("#{bin}/openssl x509 -inform pem -checkend 0 -noout", "w") do |openssl_io|
        openssl_io.write(cert)
        openssl_io.close_write
      end

      $?.success?
    end

    openssldir.mkpath
    (openssldir/"cert.pem").atomic_write(valid_certs.join("\n"))
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
