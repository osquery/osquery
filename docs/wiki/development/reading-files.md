# Reading Files

[/osquery/filesystem/filesystem.h](https://github.com/osquery/osquery/blob/master/osquery/filesystem/filesystem.h) contains utilities for accessing the filesystem.

Consider the following example for reading a file from the filesystem:

```cpp
#include <iostream>
#include <string>
#include <osquery/filesystem/filesystem.h>

const std::string kPath = "/foo/bar.txt"

int main(int argc, char* argv[]) {
  auto s = osquery::pathExists(kPath);
  if (s.ok()) {
    std::string content;
    s = osquery::readFile(kPath, content);
    if (s.ok()) {
      std::cout << "Contents of " << kPath << ":\n";
      std::cout << content;
    } else {
      std::cerr << "Error reading file: " << s.toString();
      return s.code();
    }
  } else {
    std::cerr << "The path doesn't exist\n";
    return 1;
  }
  return 0;
}
```

To internalize the main API, consider the same example without error checking:

```cpp
#include <iostream>
#include <string>
#include <osquery/filesystem/filesystem.h>

int main(int argc, char* argv[]) {
  std::string content;
  osquery::readFile("/foo/bar.txt", content);
  std::cout << "Contents of " << "/foo/bar.txt" << ":\n" << content;
  return 0;
}
```
