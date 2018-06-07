#!/usr/bin/env python

import os
import subprocess

def main():
  print("clang format check");
  if os.name == "posix":
    my_env = os.environ.copy()
    my_env["PATH"] = "/urs/local/osquery/bin/" + os.pathsep + my_env["PATH"]
    cmd = ["python", "tools/formatting/git-clang-format.py", "--diff", "--commit", "master", "--style=file"]
    p = subprocess.Popen(" ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env=my_env)
    out, err = p.communicate() 

    if not out.startswith("no modified files to format"):
      print("clang format failed")
      print("please run make format_master or apply diff:")
      print(out)
      exit(1)

if __name__ == "__main__":
  main()