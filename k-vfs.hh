#ifndef CHICKADEE_K_VFS_HH
#define CHICKADEE_K_VFS_HH

#define VFS_FILE_READ           000000000200
#define VFS_FILE_WRITE          000000000400

class vnode {
 public:
  virtual ssize_t read(char* buf, size_t sz);
  virtual ssize_t write(char* buf, size_t sz);
  // TODO: Change made during pipe:: change from close() to close_read and close_write
  // virtual void close_read();
  // virtual void close_write();
  virtual void close();

  // TODO: Change made during pipe:: a vnode only has one link from a open descriptor
};

class file {
 public:
  int perm_;
  int offset_;
  vnode* vnode_;
  int ref_count_;
  spinlock ref_count_lock_;
  void init(vnode* node, int perm);
  ssize_t vfs_read(char* buf, size_t sz);
  ssize_t vfs_write(char* buf, size_t sz);
  void vfs_close();
};

class kb_c_vnode: public vnode {
 public:
  ssize_t read(char* buf, size_t sz);
  ssize_t write(char* buf, size_t sz);
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
  ssize_t read(char* buf, size_t sz);
  ssize_t write(char* buf, size_t sz);
  void close();
};

// class pipe_vnode: public vnode {
//  public:
//   void init();
//   ssize_t read(char* buf, size_t sz);
//   ssize_t write(char* buf, size_t sz);
//   void close_read();
//   void close_write();

//  private:
//   char bbuf_[PIPE_BOUNDED_BUFFER_SIZE];
//   size_t bsize_ = PIPE_BOUNDED_BUFFER_SIZE;
//   size_t bpos_ = 0;
//   size_t blen_ = 0;
//   spinlock lock_;
//   wait_queue wq_;
//   bool write_open_;
//   bool read_open_;
// };

#endif
