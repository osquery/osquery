require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libiptables < AbstractOsqueryFormula
  desc "Device Mapper development"
  homepage "http://netfilter.samba.org/"
  url "https://osquery-packages.s3.amazonaws.com/deps/iptables-1.4.21.tar.gz"
  sha256 "ce1335c91764dc87a26978bd3725c510c2564853184c6e470e0a0f785f420f89"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "c34443f94393e351313cc35d5a0e4fd87ff25071bf4c1978b3b08829c1b3450d" => :x86_64_linux
  end

  patch :DATA

  def install
    args = [
      "--disable-shared",
    ]

    system "./configure", "--prefix=#{prefix}", *args
    cd "libiptc" do
      system "make", "install"
    end
    cd "include" do
      system "make", "install"
    end
  end
end

__END__
diff -Nur iptables-1.4.21/include/linux/netfilter_ipv4/ip_tables.h iptables-1.4.21-patched/include/linux/netfilter_ipv4/ip_tables.h
--- iptables-1.4.21/include/linux/netfilter_ipv4/ip_tables.h	2013-11-22 03:18:13.000000000 -0800
+++ iptables-1.4.21-patched/include/linux/netfilter_ipv4/ip_tables.h	2016-07-07 21:03:53.742011569 -0700
@@ -218,10 +218,11 @@
 static __inline__ struct xt_entry_target *
 ipt_get_target(struct ipt_entry *e)
 {
-	return (void *)e + e->target_offset;
+	return (struct ipt_entry_target *)((char *)e + e->target_offset);
 }
 
 /*
  *	Main firewall chains definitions and global var's definitions.
  */
 #endif /* _IPTABLES_H */
+
