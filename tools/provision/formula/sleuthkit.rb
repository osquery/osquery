require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Sleuthkit < AbstractOsqueryFormula
  desc "Forensic toolkit"
  homepage "http://www.sleuthkit.org/"
  url "https://github.com/sleuthkit/sleuthkit/archive/sleuthkit-4.2.0.tar.gz"
  sha256 "d71414134c9f8ce8e193150dd478c063173ee7f3b01f8a2a5b18c09aaa956ba7"
  head "https://github.com/sleuthkit/sleuthkit.git"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "08013b38b4e6664797c9b086af3d1af3173f2be68419f7a30af71b4e52964a89" => :el_capitan
    sha256 "a237fd15967db517aaec93001a02d98c3a4e3b95796319490426610a8cd6ffc4" => :x86_64_linux
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
