#ifndef CHICKADEE_K_VFS_HH
#define CHICKADEE_K_VFS_HH

#define VFS_FILE_READ           000000000200
#define VFS_FILE_WRITE          000000000400

class vnode {
 public:
  virtual ssize_t read(char* buf, size_t sz, size_t offset);
  virtual ssize_t write(char* buf, size_t sz, size_t offset);
  virtual ssize_t lseek(off_t offset, uint64_t flag, size_t current_offset);
  virtual void close();
};

class file {
 public:
  int id_; // index on global open file table
  int ref_count_;
  spinlock ref_count_lock_;
  vnode* vnode_; // Only public so the memviewer can access it and mark it
  file(vnode* node, int perm);
  ssize_t vfs_read(char* buf, size_t sz);
  ssize_t vfs_write(char* buf, size_t sz);
  ssize_t vfs_lseek(size_t offset, uint64_t flag);
  void vfs_close();
 private:
  int perm_;
  size_t offset_;
};

class kb_c_vnode: public vnode {
 public:
  ssize_t read(char* buf, size_t sz, size_t offset);
  ssize_t write(char* buf, size_t sz, size_t offset);
  ssize_t lseek(off_t offset, uint64_t flag, size_t current_offset);
  void close();
};

#define PIPE_BOUNDED_BUFFER_SIZE 128

class pipe {
 public:
  pipe();
  ssize_t read(char* buf, size_t sz);
  ssize_t write(char* buf, size_t sz);
  void close_read();
  void close_write();
  bool is_closed(spinlock_guard& guard);
  
  spinlock lock_;

 private:
  char bbuf_[PIPE_BOUNDED_BUFFER_SIZE];
  size_t bsize_ = PIPE_BOUNDED_BUFFER_SIZE;
  size_t bpos_ = 0;
  size_t blen_ = 0;
  wait_queue wq_;
  bool write_open_;
  bool read_open_;
};

class pipe_vnode: public vnode {
  pipe* pipe_;
  bool is_read_;
 public:
  pipe_vnode(pipe* underlying_pipe, bool is_read);
  ssize_t read(char* buf, size_t sz, size_t offset);
  ssize_t write(char* buf, size_t sz, size_t offset);
  ssize_t lseek(off_t offset, uint64_t flag, size_t current_offset);
  void close();
};

#endif
