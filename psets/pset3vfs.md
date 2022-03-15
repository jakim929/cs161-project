CS 161 Problem Set 3 VFS Design Document
========================================

```
class file {
 public:
  int ref_count_;
  spinlock ref_count_lock_;
  file(vnode* node, int perm);
  ssize_t vfs_read(char* buf, size_t sz);
  ssize_t vfs_write(char* buf, size_t sz);
  void vfs_close();

 private:
  int perm_;
  int offset_;
  vnode* vnode_;
};
class vnode {
 public:
  virtual ssize_t read(char* buf, size_t sz);
  virtual ssize_t write(char* buf, size_t sz);
  virtual void close();
};

```

Two main objects, `class vnode` and `class file`, make up my VFS layer. 

`file` is the high level abstraction for open files. It holds data agnostic to the underlying vnode_. Currently, a vnode only needs to expose three methods: read, write, close.

A vnode is only pointed to by one open file in the .

A `struct file` is an entry in the system-wide open file table. 

The system-wide open file table is called file* open_file_table[].
Each file is opened when the first 

Inside each struct proc, there is a file descriptor table file* fd_table_[]


On vnode & file creation
1. Kernel creates the appropriate vnode by using kalloc (knew<vnode>()) then calling vnode::init()
2. Kernel then creates a file object by using kalloc (knew<vnode>())
3. We pass the newly created vnode into file::init(vnode& node), which initializes the file with refcount_ = 1;
4. 

