#include <osquery/tables.h>
#include "osquery/core/windows/wmi.h"

namespace osquery {
	namespace tables {
		QueryData genLogicalDrives(QueryContext &context) {
			Row r;
			QueryData results;

			WmiRequest wmiSystemReq("select DeviceID, DriveType, FreeSpace, Size from Win32_LogicalDisk");
			std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
			for (unsigned int i = 0; i < wmiResults.size(); ++i) 
			{
				unsigned int driveType = 0;
				wmiResults[i].GetString("DeviceID", r["device_id"]);
				wmiResults[i].GetUnsignedInt32("DriveType", driveType);
				wmiResults[i].GetString("FreeSpace", r["freespace"]);
				wmiResults[i].GetString("Size", r["size"]);
				
				switch (driveType)
				{
				case 0:
					r["type"] = TEXT("UNKNOWN");
					break;

				case 1:
					r["type"] = TEXT("No Root Directory");
					break;

				case 2:
					r["type"] = TEXT("Removable Disk");
					break;

				case 3:
					r["type"] = TEXT("Local Disk");
					break;

				case 4:
					r["type"] = TEXT("Network Drive");
					break;

				case 5:
					r["type"] = TEXT("Compact Disc");
					break;

				case 6:
					r["type"] = TEXT("RAM Disk");
					break;
				}
				results.push_back(r);
			}
			return results;
		}
	}
}