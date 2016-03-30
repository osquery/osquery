#!/usr/bin/python

import os
import re
import platform
import subprocess

ORACLE_RELEASE = "/etc/oracle-release"
SYSTEM_RELEASE = "/etc/system-release"
LSB_RELEASE    = "/etc/lsb-release"
DEBIAN_VERSION = "/etc/debian_version"

def _platform():
  osType, _, _, _, _, _ = platform.uname()
  
  if osType == "Windows":
    return ("windows", "windows")
  elif osType == "Linux":
    if os.path.exists(ORACLE_RELEASE):
      return ("redhat", "oracle")
    
    if os.path.exists(SYSTEM_RELEASE):
      with open(SYSTEM_RELEASE, "r") as fd:
        fileContents = fd.read()
    
        if fileContents.find("CentOS") != -1:
          return ("redhat", "centos")
        
        if fileContents.find("Red Hat Enterprise") != -1:
          return ("redhat", "rhel")
        
        if fileContents.find("Amazon Linux") != -1:
          return ("redhat", "amazon")
        
        if fileContents.find("Fedora") != -1:
          return ("redhat", "fedora")
        
    if os.path.exists(LSB_RELEASE):
      with open(LSB_RELEASE, "r") as fd:
        fileContents = fd.read()
        
        if fileContents.find("DISTRIB_ID=Ubuntu") != -1:
          return ("debian", "ubuntu")
          
    if os.path.exists(DEBIAN_VERSION):
      return ("debian", "debian")
  else:
    return (None, osType.lower())
    
def _distro(osType):
  def getRedhatDistroVersion(pattern):
    with open(SYSTEM_RELEASE, "r") as fd:
      contents = fd.read()
      
      result = re.findall(pattern, contents)
      if result and len(result) == 1:
        return result[0].replace("release ", osType)
    return None
  
  def commandOutput(cmd):
    try:
      output = subprocess.check_output(cmd)
      return output
    except subprocess.CalledProcessError:
      return None
    except WindowsError:
      return None
      
  _, _, osVersion, _, _, _ = platform.uname()
  
  if osType == "oracle":
    result = getRedhatDistroVersion(r'release [5-7]')
    if result is not None:
      return result
  elif osType in ["centos", "rhel"]:
    result = getRedhatDistroVersion(r'release [6-7]')
    if result is not None:
      return result
  elif osType == "amazon":
    result = getRedhatDistroVersion(r'release 20[12][0-9]\.[0-9][0-9]')
    if result is not None:
      return result
  elif osType == "ubuntu":
    pass # TODO: ignoring for now
  elif osType == "darwin":
    pass # TODO: ignoring for now
  elif osType == "fedora":
    pass # TODO: ignoring for now
  elif osType == "debian":
    result = commandOutput(["lsb_release", "-cs"])
    if result is not None:
      return result
  elif osType == "freebsd":
    pass # TODO: ignoring for now
  elif osType == "windows":
    return "windows%s" % osVersion
  
  return "unknown_version"
  
if __name__ == "__main__":
  family, osType = _platform()
  distro = _distro(osType)
  print "%s;%s" % (osType, distro)
  