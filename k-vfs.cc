#include "kernel.hh"
#include "k-vfs.hh"
#include "k-devices.hh"
#include "k-wait.hh"
#include "k-waitstruct.hh"

// global open file table
file* open_file_table[N_GLOBAL_OPEN_FILES];
spinlock open_file_table_lock;

void file::init(vnode* node, int perm) {
  perm_ = perm;
  vnode_ = node;
  offset_ = 0;
  ref_count_ = 1;
}

// kb_c_vnode: vnode sub-class for keyboard and console
void kb_c_vnode::init() {
}

ssize_t kb_c_vnode::read(char* buf, size_t sz) {
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

ssize_t kb_c_vnode::write(char* buf, size_t sz) {
  log_printf("TESTING! %zu\n", sz);
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

void kb_c_vnode::close() {
    // no clean up to do
    return;
}
