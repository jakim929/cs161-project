#include "kernel.hh"
#include "k-vfs.hh"
#include "k-devices.hh"
#include "k-wait.hh"
#include "k-waitstruct.hh"

// global open file table
file* open_file_table[N_GLOBAL_OPEN_FILES];
spinlock open_file_table_lock;

file::file(vnode* node, int perm)
    : vnode_(node), perm_(perm) {
    offset_ = 0;
    ref_count_ = 1;
}

ssize_t file::vfs_read(char* buf, size_t sz) {
    if (!(perm_ & VFS_FILE_READ)) {
        return E_BADF;
    }
    ssize_t read = vnode_->read(buf, sz, offset_);
    if (read > 0) {
        offset_ += read;
    }
    return read;
}

ssize_t file::vfs_write(char* buf, size_t sz) {
    if (!(perm_ & VFS_FILE_WRITE)) {
        return E_BADF;
    }
    ssize_t written = vnode_->write(buf, sz, offset_);
    if (written > 0) {
        offset_ += written;
    }
    log_printf("vfs_write returning %zu\n", written);
    return written;
}

ssize_t file::vfs_lseek(size_t offset, uint64_t flag) {
    ssize_t retval = vnode_->lseek(offset, flag, offset_);
    // No error, should update current offset
    if (flag != LSEEK_SIZE && retval >= 0) {
        offset_ = retval;
    }
    return retval;
}

void file::vfs_close() {
    vnode_->close();
    kfree(vnode_);
}

/*
    kb_c_vnode: vnode sub-class for keyboard and console
*/
ssize_t kb_c_vnode::read(char* buf, size_t sz, size_t offset) {
  auto& kbd = keyboardstate::get();
  auto irqs = kbd.lock_.lock();

  // mark that we are now reading from the keyboard
  // (so `q` should not power off)
  if (kbd.state_ == kbd.boot) {
      kbd.state_ = kbd.input;
  }

  if (sz != 0) {
      waiter().block_until(kbd.wq_, [&] () {
          return kbd.eol_ != 0;
      }, kbd.lock_, irqs);
  }

  // read that line or lines
  size_t n = 0;
  while (kbd.eol_ != 0 && n < sz) {
      if (kbd.buf_[kbd.pos_] == 0x04) {
          // Ctrl-D means EOF
          if (n == 0) {
              kbd.consume(1);
          }
          break;
      } else {
          *reinterpret_cast<char*>(buf) = kbd.buf_[kbd.pos_];
          ++buf;
          ++n;
          kbd.consume(1);
      }
  }

  kbd.lock_.unlock(irqs);
  return n;
}

ssize_t kb_c_vnode::write(char* buf, size_t sz, size_t offset) {
    auto& csl = consolestate::get();
    spinlock_guard guard(csl.lock_);
    size_t n = 0;
    while (n < sz) {
        int ch = *reinterpret_cast<const char*>(buf);
        ++buf;
        ++n;
        console_printf(0x0F00, "%c", ch);
    }
    return n;
}

ssize_t kb_c_vnode::lseek(off_t offset, uint64_t flag, size_t current_offset) {
    return E_SPIPE;
}

void kb_c_vnode::close() {
    // no clean up to do
    return;
}

/*
    pipe_vnode: vnode sub-class for pipes
*/
pipe_vnode::pipe_vnode(pipe* underlying_pipe, bool is_read)
    : pipe_(underlying_pipe), is_read_(is_read) {
    log_printf("initializing %d\n", is_read_);
}

ssize_t pipe_vnode::read(char* buf, size_t sz, size_t offset) {
        log_printf("reading %d\n", is_read_);

    return pipe_->read(buf, sz);
}   

ssize_t pipe_vnode::write(char* buf, size_t sz, size_t offset) {
    log_printf("writing %d\n", is_read_);
    return pipe_->write(buf, sz);
}

ssize_t pipe_vnode::lseek(off_t offset, uint64_t flag, size_t current_offset) {
    return E_SPIPE;
}

void pipe_vnode::close() {
    if (is_read_) {
        pipe_->close_read();
    } else {
        pipe_->close_write();
    }
    spinlock_guard guard(pipe_->lock_);
    if (pipe_->is_closed(guard)) {
        kfree(pipe_);
    }
}

/*
    pipe: underlying data structure for a pipe
*/
pipe::pipe() {
    write_open_ = true;
    read_open_ = true;
}

ssize_t pipe::read(char* buf, size_t sz) {
    spinlock_guard guard(lock_);
    waiter().block_until(wq_, [&] () {
        return blen_ > 0 || !write_open_;
    }, guard);

    size_t read = 0;
    while (read < sz && blen_ > 0) {
      buf[read] = bbuf_[bpos_];
      bpos_ = (bpos_ + 1) % bsize_;
      blen_--;
      read++;
    }
    assert(!write_open_ || read > 0 || current()->tg_->should_exit_);
    wq_.wake_all();
    return read;
}

ssize_t pipe::write(char* buf, size_t sz) {
    spinlock_guard guard(lock_);
    if (!read_open_) {
        return E_PIPE;
    }
    waiter().block_until(wq_, [&] () {
        return bsize_ - blen_ >= sz || !read_open_;
    }, guard);

    size_t written = 0;
    while (written < sz && blen_ < bsize_) {
        size_t id = (this->bpos_ + this->blen_) % bsize_;
        bbuf_[id] = buf[written];
        blen_++;
        written++;
    }
    assert(written > 0);
    wq_.wake_all();
    return written;
}

void pipe::close_read() {
    spinlock_guard guard(lock_);
    read_open_ = false;
    wq_.wake_all();
    return;
}

void pipe::close_write() {
    spinlock_guard guard(lock_);
    write_open_ = false;
    wq_.wake_all();
    return;
}

bool pipe::is_closed(spinlock_guard& guard) {
    return !read_open_ && !write_open_;
}
