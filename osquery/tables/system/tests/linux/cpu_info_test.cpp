/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <linux/raid/md_p.h>
#include <linux/raid/md_u.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utility>

#include <osquery/tables/system/linux/cpu_info.h>

using namespace testing;

namespace osquery {
namespace tables {

class CpuInfoTest : public ::testing::Test {};

static const std::string kProcCpuInfoSample = R"CpuInfo(
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 42
model name	: Intel(R) Core(TM) i5-2400 CPU @ 3.10GHz
stepping	: 7
microcode	: 0x2f
cpu MHz		: 3400.000
cache size	: 6144 KB
physical id	: 0
siblings	: 4
core id		: 0
cpu cores	: 4
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ht tm pbe syscall nx rdtscp lm constant_tsc arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx lahf_lm epb pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid xsaveopt dtherm ida arat pln pts md_clear flush_l1d
vmx flags	: vnmi preemption_timer invvpid ept_x_only flexpriority tsc_offset vtpr mtf vapic ept vpid unrestricted_guest
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit
bogomips	: 6188.43
clflush size	: 64
cache_alignment	: 64
address sizes	: 36 bits physical, 48 bits virtual
power management:

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 42
model name	: Intel(R) Core(TM) i5-2400 CPU @ 3.10GHz
stepping	: 7
microcode	: 0x2f
cpu MHz		: 1795.084
cache size	: 6144 KB
physical id	: 0
siblings	: 4
core id		: 1
cpu cores	: 4
apicid		: 2
initial apicid	: 2
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ht tm pbe syscall nx rdtscp lm constant_tsc arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx lahf_lm epb pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid xsaveopt dtherm ida arat pln pts md_clear flush_l1d
vmx flags	: vnmi preemption_timer invvpid ept_x_only flexpriority tsc_offset vtpr mtf vapic ept vpid unrestricted_guest
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit
bogomips	: 6188.43
clflush size	: 64
cache_alignment	: 64
address sizes	: 36 bits physical, 48 bits virtual
power management:

processor	: 2
vendor_id	: GenuineIntel
cpu family	: 6
model		: 42
model name	: Intel(R) Core(TM) i5-2400 CPU @ 3.10GHz
stepping	: 7
microcode	: 0x2f
cpu MHz		: 1600.000
cache size	: 6144 KB
physical id	: 0
siblings	: 4
core id		: 2
cpu cores	: 4
apicid		: 4
initial apicid	: 4
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ht tm pbe syscall nx rdtscp lm constant_tsc arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx lahf_lm epb pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid xsaveopt dtherm ida arat pln pts md_clear flush_l1d
vmx flags	: vnmi preemption_timer invvpid ept_x_only flexpriority tsc_offset vtpr mtf vapic ept vpid unrestricted_guest
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit
bogomips	: 6188.43
clflush size	: 64
cache_alignment	: 64
address sizes	: 36 bits physical, 48 bits virtual
power management:

processor	: 3
vendor_id	: GenuineIntel
cpu family	: 6
model		: 42
model name	: Intel(R) Core(TM) i5-2400 CPU @ 3.10GHz
stepping	: 7
microcode	: 0x2f
cpu MHz		: 1600.000
cache size	: 6144 KB
physical id	: 0
siblings	: 4
core id		: 3
cpu cores	: 4
apicid		: 6
initial apicid	: 6
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ht tm pbe syscall nx rdtscp lm constant_tsc arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx lahf_lm epb pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid xsaveopt dtherm ida arat pln pts md_clear flush_l1d
vmx flags	: vnmi preemption_timer invvpid ept_x_only flexpriority tsc_offset vtpr mtf vapic ept vpid unrestricted_guest
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit
bogomips	: 6188.43
clflush size	: 64
cache_alignment	: 64
address sizes	: 36 bits physical, 48 bits virtual
power management:
)CpuInfo";

TEST_F(CpuInfoTest, parsesText) {
  std::vector<CpuInfo> cpu_info = parseCpuInfo("");
  EXPECT_EQ(cpu_info.size(), 0);
  cpu_info = parseCpuInfo(kProcCpuInfoSample);
  EXPECT_EQ(cpu_info.size(), 1);
  EXPECT_EQ(cpu_info[0].device_id, "0");
  EXPECT_EQ(cpu_info[0].socket_designation, "0");
  EXPECT_EQ(cpu_info[0].model, "Intel(R) Core(TM) i5-2400 CPU @ 3.10GHz");
  EXPECT_EQ(cpu_info[0].manufacturer, "GenuineIntel");
  EXPECT_EQ(cpu_info[0].number_of_cores, "4");
  EXPECT_EQ(cpu_info[0].logical_processors, "4");
  EXPECT_EQ(cpu_info[0].address_width, "64");
  EXPECT_EQ(cpu_info[0].current_clock_speed, "3400.000");
}

} // namespace tables
} // namespace osquery
