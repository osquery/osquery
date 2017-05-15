require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Sleuthkit < AbstractOsqueryFormula
  desc "Forensic toolkit"
  homepage "http://www.sleuthkit.org/"
  url "https://github.com/sleuthkit/sleuthkit/archive/sleuthkit-4.3.0.tar.gz"
  sha256 "64a57a44955e91300e1ae69b34e8702afda0fb5bd72e2116429875c9f5f28980"
  head "https://github.com/sleuthkit/sleuthkit.git"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "6fcccb0afc71188b5703ed8129f361ba58fc2b277c1b916dd8ac028ebd9144f3" => :sierra
    sha256 "d454fdb7bd7d4fa2870733f324d9f2e34eddf3ef471cbb3a2a2bc2ce504eb9ec" => :x86_64_linux
  end

  conflicts_with "irods", :because => "both install `ils`"

  option "with-jni", "Build Sleuthkit with JNI bindings"
  option "with-debug", "Build debug version"

  if build.with? "jni"
    depends_on :java
    depends_on :ant => :build
  end

  depends_on "autoconf" => :build
  depends_on "automake" => :build
  depends_on "libtool" => :build
  depends_on "afflib" => :optional
  depends_on "libewf" => :optional

  conflicts_with "ffind",
    :because => "both install a 'ffind' executable."

  def install
    ENV.java_cache if build.with? "jni"

    system "./bootstrap"
    system "./configure", "--disable-dependency-tracking",
                          if build.without? "jni" then "--disable-java" end,
                          "--disable-shared",
                          "--enable-static",
                          "--prefix=#{prefix}"
    system "make"
    system "make", "install"

    if build.with? "jni"
      cd "bindings/java" do
        system "ant"
      end
      prefix.install "bindings"
    end
  end

  test do
    system "#{bin}/tsk_loaddb", "-V"
  end
end
