#ifndef CHICKADEE_K_VFS_HH
#define CHICKADEE_K_VFS_HH

#define VFS_FILE_READ           000000000200
#define VFS_FILE_WRITE          000000000400

class vnode {
 public:
  virtual ssize_t read(char* buf, size_t sz);
  virtual ssize_t write(char* buf, size_t sz);
  virtual void init();
};

class file {
 public:
  int perm_;
  int offset_;
  vnode* vnode_;
  int ref_count_;
  spinlock ref_count_lock_;
  void init(vnode* node, int perm);
};

class kb_c_vnode: public vnode {
 public:
  ssize_t read(char* buf, size_t sz);
  ssize_t write(char* buf, size_t sz);
  void init();
};

class file_vnode: public vnode {

};

class pipe_vnode: public vnode {

};



#endif
