#ifndef CHICKADEE_K_VFS_HH
#define CHICKADEE_K_VFS_HH

#define VFS_FILE_READ           000000000200
#define VFS_FILE_WRITE          000000000400

// TODO: After memfs, i had to add offset in order to keep track of last read position
// this is tracked in the file::read level
class vnode {
 public:
  virtual ssize_t read(char* buf, size_t sz, size_t offset);
  virtual ssize_t write(char* buf, size_t sz, size_t offset);
  // TODO: Change made during pipe:: change from close() to close_read and close_write
  // virtual void close_read();
  // virtual void close_write();
  virtual void close();

  // TODO: Change made during pipe:: a vnode only has one link from a open descriptor
};

class file {
  // TODO: add index inside open file table
 public:
  int id_; // index on global open file table
  int ref_count_;
  spinlock ref_count_lock_;
  file(vnode* node, int perm);
  ssize_t vfs_read(char* buf, size_t sz);
  ssize_t vfs_write(char* buf, size_t sz);
  void vfs_close();
 private:
  int perm_;
  size_t offset_;
  vnode* vnode_;
};

class kb_c_vnode: public vnode {
 public:
  ssize_t read(char* buf, size_t sz, size_t offset);
  ssize_t write(char* buf, size_t sz, size_t offset);
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
