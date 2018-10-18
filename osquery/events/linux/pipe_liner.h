#ifndef _PIPE_LINER_H_
#define _PIPE_LINER_H_

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

// default max syslog line is 1024, but can be configured as high as 8192

#define LINE_BUF_MAX 16384

struct PipeLinerListener {
  virtual void onLine(std::string line) = 0;
  virtual ~PipeLinerListener() {}
};

/**
 * A non-blocking buffered line reader that uses select()
 */
struct PipeLiner {
  PipeLiner(PipeLinerListener* listener, uint32_t chunksize = 4096)
      : chunksize_(chunksize),
        path_(),
        fd_(0),
        buf_(),
        listener_(listener),
        tmpbuf_(chunksize) {
    buf_.reserve(chunksize_ * 2);
  }
  ~PipeLiner() {}

  /**
   * Open the pipe file read-only and non-blocking.
   * @returns true on error, false on success
   */
  bool open(std::string pipe_file_path) {
    if (path_.size() > 0) {
      return true;
    }
    path_ = pipe_file_path;
    fd_ = ::open(path_.c_str(), O_RDONLY | O_NONBLOCK);

    return (fd_ <= 0);
  }

  /**
   * reads data and calls listener_.onLine() with any new lines.
   * @returns -1 if select() error, 0 timeout waiting for data, 1 if data read.
   */
  int update() {
    fd_set set;
    struct timeval timeout = {timeout_sec_, (int)timeout_usec_};

    FD_ZERO(&set); /* clear the set */
    FD_SET(fd_, &set); /* add our file descriptor to the set */

    // is data available?

    int rv = select(fd_ + 1, &set, NULL, NULL, &timeout);
    if (rv == -1) {
      return rv; // error
    } else if (rv == 0) {
      return rv; // timeout waiting for data
    }

    // Only iterate N times, rather than getting stuck when lots of data.
    // If chunksize is 4096, but line is 8192 bytes, it will take a couple of
    // reads to get it all.

    for (int i = 0; i < read_loop_count_; i++) {
      // setup a pointer to end of existing data in buffer

      ssize_t avail = read(fd_, tmpbuf_.data(), tmpbuf_.size() - 1);
      if (avail > 0) {
        tmpbuf_[avail] = 0; // add null terminator

        _onBuffer(tmpbuf_.data(), avail);
      }

      // if read less than size of buffer, no need to loop

      if (avail < (ssize_t)(tmpbuf_.size() - 1))
        break;
    }

    return 1;
  }

  /*
   * close file if opened
   */
  void close() {
    if (fd_ <= 0) {
      return;
    }

    ::close(fd_);
    fd_ = 0;
  }

  /*
   * Process a chunk of data from pipe.
   * It may or may not include a full line.
   */
  void _onBuffer(const char* tmpbuf, ssize_t avail) {
    const char* ptr = tmpbuf;
    size_t remaining = (size_t)avail;

    // check for existing partial line in buf_

    if (buf_.size() > 0) {
      auto existingSize = buf_.size();

      if ((existingSize + avail) > LINE_BUF_MAX) {
        // drop existing data
        buf_.resize(0);

      } else {
        // append
        buf_.resize(existingSize + avail);
        memcpy(buf_.data() + existingSize, tmpbuf, avail);

        // overwrite local tracking vars to use _buf
        ptr = buf_.data();
        remaining = buf_.size();
      }
    }

    // process lines in buffer

    while (remaining > 0) {
      // find end of line

      auto end = ptr + remaining;
      auto pos = ptr;
      while (pos < end && *pos != '\n') {
        pos++;
      }

      if (pos == end) {
        // no end of line
        _stash((char*)ptr, remaining);
        return;
      }

      // send to listener

      auto line = std::string(ptr, pos - ptr);
      auto len = line.size();
      if (listener_ != 0L) {
        listener_->onLine(line);
      }

      ptr += len + 1;
      remaining -= len + 1;
    }

    // We were able to read entire buffer - shrink buf_

    if (buf_.size() > 0) {
      buf_.resize(0);
    }
  }

  /*
   * have a partial line, store in buf_ for now
   */
  void _stash(char* ptr, size_t len) {
    // copy to a temp vector

    auto tmp = std::vector<char>(len);
    memcpy(tmp.data(), ptr, len);

    // add more capacity if needed for next read

    if ((buf_.capacity() - len) < chunksize_) {
      buf_.reserve(buf_.size() * 2);
    }

    // copy to buf_

    buf_.resize(len);
    memcpy(buf_.data(), tmp.data(), len);
  }

  uint32_t chunksize_;
  std::string path_;
  int fd_;
  std::vector<char> buf_; // used if partial lines remain from last read
  PipeLinerListener* listener_;
  uint32_t timeout_sec_{0};
  uint32_t timeout_usec_{500000}; // 500ms
  int read_loop_count_{3};
  std::vector<char> tmpbuf_; // buffer filled with read()
};

#endif // _PIPE_LINER_H_
