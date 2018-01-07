require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Openipmi < AbstractOsqueryFormula
  desc "OpenIPMI is an effort to create a full-function IPMI system to allow full access to all IPMI information on a server and to abstract it to a level that will make it easy to use"
  homepage "http://openipmi.sourceforge.net/"
  license "LGPL-2.1+"
  url "https://sourceforge.net/projects/openipmi/files/OpenIPMI%202.0%20Library/OpenIPMI-2.0.23.tar.gz"
  sha256 "035c5cc0566dd161c3a6528e5a5e8982c960a0fe3619564831397c46552f8b68"
  revision 102

  # Avoid building lanserv
  patch :DATA

  depends_on "autoconf" => :build
  depends_on "automake" => :build
  depends_on "libtool" => :build
  depends_on "pkg-config" => :build
  depends_on "ncurses"
  depends_on "popt"

  def install
    args = [
      "--prefix=#{prefix}",
      "--enable-shared=no",
    ]

    ENV.append "PERL5LIB", "#{default_prefix}/Cellar/autoconf/2.69/share/autoconf"

    system "autoreconf"
    system "./configure", *args
    system "make"
    system "make", "install", "-i"
  end
end

__END__
diff --git a/Makefile.am b/Makefile.am
index b1aacdf..e72af23 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -2,10 +2,10 @@ RPM		= rpmbuild
 RPMFLAGS	= -ta

 SUBDIRS    = include utils lib unix $(GLIB_DIR) $(TCL_DIR) libedit cmdlang \
-	     ui lanserv sample doc man $(SWIG_DIR)
+	     ui sample doc man $(SWIG_DIR)

 DIST_SUBDIRS = include utils lib unix glib tcl libedit cmdlang \
-	     ui lanserv sample doc man swig
+	     ui sample doc man swig

 EXTRA_DIST = FAQ TODO README.Force README.MotorolaMXP OpenIPMI.spec.in \
 	     OpenIPMI.spec ipmi.init ipmi.sysconf COPYING.BSD \
