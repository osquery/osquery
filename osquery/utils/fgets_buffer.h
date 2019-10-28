#pragma once

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

#include <osquery/filesystem/fileops.h>

struct NonblockingFile {
  virtual bool isValid() = 0;

  virtual bool isDataAvail() = 0;

  virtual ssize_t read(std::vector<char>& buf) = 0;

  virtual void close() = 0;
};

typedef std::shared_ptr<NonblockingFile> SPNonblockingFile;

/**
 * Implementation of non-blocking file access.
 */
class NonblockingFileImpl : public NonblockingFile {
  NonblockingFileImpl(std::string filepath,
                      uint32_t selectTimeoutUsec = 5000000)
      : NonblockingFile(),
        path_(filepath),
        selectTimeoutUsec_(selectTimeoutUsec) {
    fd_ = ::open(path_.c_str(), O_RDONLY | O_NONBLOCK);
  }

  virtual ~NonblockingFileImpl() {}

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
    struct timeval timeout = {0, (int)selectTimeoutUsec_};

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
  ssize_t read(std::vector<char>& buf) override {
    char tmpbuf[4096];
    size_t remaining = buf.capacity() - buf.size();
    auto len = (remaining > sizeof(tmpbuf) ? sizeof(tmpbuf) : remaining);
    ssize_t bytesRead = ::read(fd_, tmpbuf, len);

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

class FgetsBuffer {
 public:
  /**
   * If includeNewline is true, then strings returned by fgets() will
   * have newline character at the end (like stdio behavior).
   */
  FgetsBuffer(SPNonblockingFile spFile,
              size_t maxLineLen = 16384,
              bool includeNewline = false)
      : spFile_(spFile),
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

      ssize_t bytesRead = spFile_->read(buf_);
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
    char* pos = strnstr(buf_.data(), "\n", buf_.size());
    if (NULL == pos) {
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

  SPNonblockingFile spFile_;
  std::vector<char> buf_;
  size_t maxLineLen_;
  size_t droppedChars_{0};
  bool includeNewline_;
};
