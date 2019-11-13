/**
 *  Copyright (c) 2019-present, osquery Foundation
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <osquery/filesystem/fileops.h>

class fgetsTest;

/*
 * This all exists to ensure that we don't get hangs when
 * using fgets() on pipes.  See issue #4810 for details.
 */

/**
 * @brief Abstraction of a non blocking file for use with FgetsBuffer
 */
struct NonblockingFile {
  virtual bool isValid() = 0;

  virtual bool isDataAvail() = 0;

  virtual int64_t read(std::vector<char>& buf) = 0;

  virtual void close() = 0;

  virtual ~NonblockingFile() {}
};

typedef std::unique_ptr<NonblockingFile> NonblockingFileRef;

#ifdef OSQUERY_POSIX

/**
 * Implementation of non-blocking file access.
 */
class NonblockingFileImpl : public NonblockingFile {
 public:
  NonblockingFileImpl(std::string filepath,
                      uint32_t selectTimeoutUsec = 5000000)
      : NonblockingFile(),
        path_(filepath),
        selectTimeoutUsec_(selectTimeoutUsec) {
    fd_ = ::open(path_.c_str(), O_RDONLY | O_NONBLOCK);
  }

  virtual ~NonblockingFileImpl() {
    if (fd_ > 0) {
      ::close(fd_);
    }
  }

  /**
   * If unable to open file in constructor, or
   * close() has been called, this will return false.
   */
  bool isValid() override {
    return fd_ > 0;
  }

  /**
   * @return true if select() shows data is available for reading.
   */
  bool isDataAvail() override {
    fd_set set;
    struct timeval timeout = {0, static_cast<int>(selectTimeoutUsec_)};

    FD_ZERO(&set); /* clear the set */
    FD_SET(fd_, &set); /* add our file descriptor to the set */

    int rv = select(fd_ + 1, &set, NULL, NULL, &timeout);
    if (rv == -1) {
      // TODO : after a certain number of these, shut it down?
    }
    return rv > 0;
  }

  /**
   * Reads data from file, appending to buf upto capacity.
   * @return number of bytes read, -1 on error, 0 on none.
   */
  int64_t read(std::vector<char>& buf) override {
    char tmpbuf[4096];
    size_t remaining = buf.capacity() - buf.size();
    auto len = (remaining > sizeof(tmpbuf) ? sizeof(tmpbuf) : remaining);
    int64_t bytesRead = ::read(fd_, tmpbuf, len);

    if (bytesRead > 0) {
      auto p = buf.data() + buf.size();
      buf.resize(buf.size() + bytesRead);
      memcpy(p, tmpbuf, bytesRead);
    }
    return bytesRead;
  }

  void close() override {
    if (fd_ > 0) {
      ::close(fd_);
      fd_ = 0;
    }
  }

 protected:
  std::string path_;
  int fd_{-1};
  uint32_t selectTimeoutUsec_;
};
#endif // OSQUERY_POSIX

class FgetsBuffer {
 public:
  /**
   * If includeNewline is true, then strings returned by fgets() will
   * have newline character at the end (like stdio behavior).
   */
  FgetsBuffer(NonblockingFileRef spFile,
              size_t maxLineLen = 16384,
              bool includeNewline = false)
      : spFile_(std::move(spFile)),
        buf_(),
        maxLineLen_(maxLineLen),
        includeNewline_(includeNewline) {
    buf_.reserve(maxLineLen);
  }

  /**
   * If buffer reaches maxLineLen without a newline,
   * buffer is cleared.  This counter returns number of
   * chars dropped.
   */
  size_t getNumDroppedChars() {
    return droppedChars_;
  }

  /// return false on success getting a line into dest, true on timeout or error
  bool fgets(std::string& dest) {
    if (!spFile_->isValid()) {
      return true;
    }

    // first see if a line is already buffered

    if (!buf_.empty() && !_gets(dest)) {
      return false;
    }

    if (spFile_->isDataAvail()) {
      // read more

      int64_t bytesRead = spFile_->read(buf_);
      if (bytesRead > 0) {
        // try again to see if entire line is available

        return _gets(dest);
      }
    }
    return true;
  }

 protected:
  /**
   *
   * @return true on error, false if able to get a line into dest
   */
  bool _gets(std::string& dest) {
    char* pos = reinterpret_cast<char*>(memchr(buf_.data(), '\n', buf_.size()));
    if (nullptr == pos) {
      if (buf_.size() >= maxLineLen_) {
        // blow it all away
        droppedChars_ += buf_.size();
        buf_.clear();
      }
      return true;
    }

    // copy string

    auto len = pos - buf_.data();
    auto destlen = (includeNewline_ ? len + 1 : len);
    dest = std::string(buf_.data(), destlen);

    // adjust by one to omit newline

    auto remaining = buf_.size() - len - 1;
    memmove(buf_.data(), pos + 1, remaining);
    buf_.resize(remaining);

    return false;
  }

 private:
  NonblockingFileRef spFile_;
  std::vector<char> buf_;
  size_t maxLineLen_;
  size_t droppedChars_{0};
  bool includeNewline_;

  friend fgetsTest;
};
