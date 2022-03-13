CS 161 Problem Set 3 VFS Design Document
========================================

`struct vnode` and `struct file` make up my VFS layer.

A `struct file` is an entry in the system-wide open file table. 

The system-wide open file table is called file* open_file_table[].
Each file is opened when the first 

Inside each struct proc, there is 


On vnode & file creation
1. Kernel creates the appropriate vnode by using kalloc (knew<vnode>()) then calling vnode::init()
2. Kernel then creates a file object by using kalloc (knew<vnode>())
3. We pass the newly created vnode into file::init(vnode& node), which initializes the file with refcount_ = 1;
4. 
