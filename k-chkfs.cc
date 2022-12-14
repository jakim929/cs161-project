#include "k-chkfs.hh"
#include "k-ahci.hh"
#include "k-chkfsiter.hh"
#include "lib.hh"

bufcache bufcache::bc;

bufcache::bufcache() {
}


// bufcache::get_disk_entry(bn, cleaner)
//    Reads disk block `bn` into the buffer cache, obtains a reference to it,
//    and returns a pointer to its bcentry. The returned bcentry has
//    `buf_ != nullptr` and `estate_ >= es_clean`. The function may block.
//
//    If this function reads the disk block from disk, and `cleaner != nullptr`,
//    then `cleaner` is called on the entry to clean the block data.
//
//    Returns `nullptr` if there's no room for the block.

bcentry* bufcache::get_disk_entry(chkfs::blocknum_t bn,
                                  bcentry_clean_function cleaner) {
    assert(chkfs::blocksize == PAGESIZE);
    auto irqs = lock_.lock();

    // look for slot containing `bn`
    size_t i, empty_slot = -1;
    for (i = 0; i != ne; ++i) {
        if (e_[i].empty()) {
            if (empty_slot == size_t(-1)) {
                empty_slot = i;
            }
        } else if (e_[i].bn_ == bn) {
            break;
        }
    }

    // if not found, use free slot
    if (i == ne) {
        if (empty_slot == size_t(-1)) {
            empty_slot = maybe_evict(irqs);
            if (empty_slot == size_t(-1)) {
                // cache full!
                lock_.unlock(irqs);
                sync(0);
                irqs = lock_.lock();
                empty_slot = maybe_evict(irqs);
                if (empty_slot == size_t(-1)) {
                    lock_.unlock(irqs);
                    log_printf("bufcache: no room for block %u\n", bn);
                    return nullptr;
                }
            }
        }
        i = empty_slot;
    }

    // obtain entry lock
    e_[i].lock_.lock_noirq();

    // mark allocated if empty
    if (e_[i].empty()) {
        e_[i].estate_ = bcentry::es_allocated;
        e_[i].bn_ = bn;
    } 

    // no longer need cache lock
    lock_.unlock_noirq();

    // mark reference
    ++e_[i].ref_;

    {
        spinlock_guard eviction_queue_guard(eviction_queue_lock_);
        spinlock_guard dirty_queue_guard(dirty_queue_lock_);
        if (e_[i].estate_ == bcentry::es_dirty) {
            assert(!e_[i].eviction_queue_link_.is_linked());
            assert(e_[i].dirty_queue_link_.is_linked());
        }
        if (e_[i].eviction_queue_link_.is_linked()) {
            e_[i].eviction_queue_link_.erase();
        }
    }

    // load block
    bool ok = e_[i].load(irqs, cleaner);

    assert(ok);

    // unlock and return entry
    if (!ok) {
        --e_[i].ref_;
    }
    e_[i].lock_.unlock(irqs);

    if (!ok) {
        spinlock_guard guard(lock_);
        eviction_queue_.push_front(&e_[i]);
    }
    return ok ? &e_[i] : nullptr;
}

bcentry* bufcache::get_disk_entry_for_prefetch(chkfs::blocknum_t bn,
                                  bcentry_clean_function cleaner) {
    assert(chkfs::blocksize == PAGESIZE);
    auto irqs = lock_.lock();

    // look for slot containing `bn`
    size_t i, empty_slot = -1;
    for (i = 0; i != ne; ++i) {
        if (e_[i].empty()) {
            if (empty_slot == size_t(-1)) {
                empty_slot = i;
            }
        } else if (e_[i].bn_ == bn) {
            break;
        }
    }

    // if not found, use free slot
    if (i == ne) {
        if (empty_slot == size_t(-1)) {
            empty_slot = maybe_evict(irqs);
            if (empty_slot == size_t(-1)) {
                // cache full!
                lock_.unlock(irqs);
                sync(0);
                irqs = lock_.lock();
                empty_slot = maybe_evict(irqs);
                if (empty_slot == size_t(-1)) {
                    lock_.unlock(irqs);
                    log_printf("bufcache: no room for block %u\n", bn);
                    return nullptr;
                }
            }
        }
        i = empty_slot;
    }

    // obtain entry lock
    e_[i].lock_.lock_noirq();

    // mark allocated if empty
    if (e_[i].empty()) {
        e_[i].estate_ = bcentry::es_allocated;
        e_[i].bn_ = bn;
    } 

    // no longer need cache lock
    lock_.unlock_noirq();

    // mark reference
    ++e_[i].ref_;

    {
        spinlock_guard eviction_queue_guard(eviction_queue_lock_);
        spinlock_guard dirty_queue_guard(dirty_queue_lock_);
        if (e_[i].estate_ == bcentry::es_dirty) {
            assert(!e_[i].eviction_queue_link_.is_linked());
            assert(e_[i].dirty_queue_link_.is_linked());
        }
        if (e_[i].eviction_queue_link_.is_linked()) {
            e_[i].eviction_queue_link_.erase();
        }
    }

    // load block
    bool ok = e_[i].load_for_prefetch(irqs, cleaner);

    assert(ok);

    // unlock and return entry
    if (!ok) {
        --e_[i].ref_;
    }
    e_[i].lock_.unlock(irqs);

    if (!ok) {
        spinlock_guard guard(lock_);
        eviction_queue_.push_front(&e_[i]);
    }
    return ok ? &e_[i] : nullptr;
}

void bufcache::prefetch(chkfs::blocknum_t bn, int n) {
    spinlock_guard guard(prefetch_queue_lock_);
    for (int k = bn; k < bn + n; k++) {
        for (int i = 0; i < 32; i++) {
            int id = i + bc.prefetch_queue_head_;
            if (prefetch_queue_[id % 32].bn_ == -1) {
                prefetch_queue_[id % 32].bn_ = k;
                break;
            }
        }
    }

    prefetch_wait_queue_.wake_all();
    return;
}

size_t bufcache::maybe_evict(irqstate& irqs) {
    bcentry* lru_bcentry = nullptr;
    {
        spinlock_guard eviction_queue_guard(eviction_queue_lock_);
        for (bcentry* a = eviction_queue_.back(); a; a = bc.eviction_queue_.prev(a)) {
            spinlock_guard guard(a->lock_);
            if (a->estate_.load() != bcentry::es_prefetching) {
                lru_bcentry = a;
                break;
            }
        }
        if (lru_bcentry) {
            lru_bcentry->eviction_queue_link_.erase();
        }
    }

    if (!lru_bcentry) {
        return -1;
    }

    assert(lru_bcentry->estate_ != bcentry::es_dirty);

    {
        spinlock_guard bcentry_guard(lru_bcentry->lock_);
        assert(lru_bcentry->estate_ != bcentry::es_dirty);
        lru_bcentry->clear();
    }
    return lru_bcentry->index();
}


// bcentry::load(irqs, cleaner)
//    Completes the loading process for a block. Requires that `lock_` is
//    locked, that `estate_ >= es_allocated`, and that `bn_` is set to the
//    desired block number.

bool bcentry::load(irqstate& irqs, bcentry_clean_function cleaner) {
    bufcache& bc = bufcache::get();
    // load block, or wait for concurrent reader to load it
    while (true) {
        assert(estate_ != es_empty);
        if (estate_ == es_allocated) {
            assert(fetch_status_.load() != E_AGAIN);
            if (!buf_) {
                buf_ = reinterpret_cast<unsigned char*>
                    (kalloc(chkfs::blocksize));
                if (!buf_) {
                    return false;
                }
            }
            estate_ = es_loading;
            lock_.unlock(irqs);

            sata_disk->read(buf_, chkfs::blocksize,
                            bn_ * chkfs::blocksize);

            irqs = lock_.lock();
            estate_ = es_clean;
            if (cleaner) {
                cleaner(this);
            }
            bc.read_wq_.wake_all();
        } else if (estate_ == es_loading || estate_ == es_prefetching) {
            waiter().block_until(bc.read_wq_, [&] () {
                    return estate_.load() != es_loading && estate_.load() != es_prefetching;
                }, lock_, irqs);
        } else {
            return true;
        }
    }
}


bool bcentry::load_for_prefetch(irqstate& irqs, bcentry_clean_function cleaner) {
    bufcache& bc = bufcache::get();
    // load block, or wait for concurrent reader to load it
    while (true) {
        assert(estate_ != es_empty);
        if (estate_ == es_allocated) {
            assert(fetch_status_.load() != E_AGAIN);
            if (!buf_) {
                buf_ = reinterpret_cast<unsigned char*>
                    (kalloc(chkfs::blocksize));
                if (!buf_) {
                    return false;
                }
            }
            estate_ = es_prefetching;
            lock_.unlock(irqs);

            sata_disk->read(buf_, chkfs::blocksize,
                            bn_ * chkfs::blocksize);

            irqs = lock_.lock();
            estate_ = es_clean;
            if (cleaner) {
                cleaner(this);
            }
            bc.read_wq_.wake_all();
        } else if (estate_ == es_loading || estate_ == es_prefetching) {
            waiter().block_until(bc.read_wq_, [&] () {
                    return estate_.load() != es_prefetching && estate_.load() != es_loading;
                }, lock_, irqs);
        } else {
            return true;
        }
    }
}


// bcentry::put()
//    Releases a reference to this buffer cache entry. The caller must
//    not use the entry after this call.

void bcentry::put() {
    bufcache* bc = &bufcache::get();
    spinlock_guard guard(lock_);
    assert(ref_ != 0);
    assert(!eviction_queue_link_.is_linked());
    if (--ref_ == 0) {
        assert(!eviction_queue_link_.is_linked());
        spinlock_guard eviction_queue_guard(bc->eviction_queue_lock_);
        // Add to LRU queue instead of clearing
        if (estate_ != es_dirty) {
            assert(!dirty_queue_link_.is_linked());
            if (bn_ != 0) {
                bc->eviction_queue_.push_back(this);
            }
        } else {
            assert(dirty_queue_link_.is_linked());
        }
    }
}


// bcentry::get_write()
//    Obtains a write reference for this entry.

void bcentry::get_write() {
    spinlock_guard guard(lock_);

    waiter().block_until(write_reference_wq_, [&] () {
        return write_reference_ == 0;
    }, guard);

    assert(write_reference_ == 0);
    write_reference_ = 1;
    
    bufcache* bc = &bufcache::get();
    spinlock_guard dirty_queue_guard(bc->dirty_queue_lock_);

    bool was_previously_dirty = estate_ == es_dirty;
    estate_ = es_dirty;

    assert(!(this->ref_ > 0 && this->eviction_queue_link_.is_linked()));

    if (was_previously_dirty) {
    } else if (!was_previously_dirty && !this->dirty_queue_link_.is_linked()) {
        bc->dirty_queue_.push_back(this);
    }
}

// bcentry::put_write()
//    Releases a write reference for this entry.

void bcentry::put_write() {
    spinlock_guard guard(lock_);
    assert(write_reference_ == 1);
    write_reference_ = 0;
}


// bufcache::sync(drop)
//    Writes all dirty buffers to disk, blocking until complete.
//    If `drop > 0`, then additionally free all buffer cache contents,
//    except referenced blocks. If `drop > 1`, then assert that all inode
//    and data blocks are unreferenced.

int bufcache::sync(int drop) {
    // write dirty buffers to disk
    // Your code here!
    list<bcentry, &bcentry::dirty_queue_link_> temp_dirty_queue_;
    {
        spinlock_guard dirty_queue_guard(dirty_queue_lock_);
        temp_dirty_queue_.swap(dirty_queue_);
    }
    while (bcentry* e = temp_dirty_queue_.pop_front()) {
        e->get_write();
        assert(!e->dirty_queue_link_.is_linked());
        assert(!e->eviction_queue_link_.is_linked());
        sata_disk->write(e->buf_, chkfs::blocksize, chkfs::blocksize * e->bn_);
        e->put_write();
        spinlock_guard(e->lock_);
        e->estate_ = bcentry::es_clean;
        if (e->ref_ == 0) {
            eviction_queue_.push_back(e);
        }
    }

    // drop clean buffers if requested
    if (drop > 0) {
        spinlock_guard guard(lock_);
        for (size_t i = 0; i != ne; ++i) {
            spinlock_guard eguard(e_[i].lock_);

            // validity checks: referenced entries aren't empty; if drop > 1,
            // no data blocks are referenced
            assert(e_[i].ref_ == 0 || e_[i].estate_ != bcentry::es_empty);
            if (e_[i].ref_ > 0 && drop > 1 && e_[i].bn_ >= 2 && e_[i].estate_.load() != bcentry::es_prefetching) {
                error_printf(CPOS(22, 0), COLOR_ERROR, "sync(2): block %u has nonzero reference count\n", e_[i].bn_);
                assert_fail(__FILE__, __LINE__, "e_[i].bn_ < 2");
            }

            // actually drop buffer
            if (e_[i].ref_ == 0 && e_[i].bn_ != 0) {
                e_[i].clear();
            }
        }
    }

    return 0;
}


// inode lock functions
//    The inode lock protects the inode's size and data references.
//    It is a read/write lock; multiple readers can hold the lock
//    simultaneously.
//
//    IMPORTANT INVARIANT: If a kernel task has an inode lock, it
//    must also hold a reference to the disk page containing that
//    inode.

namespace chkfs {

void inode::lock_read() {
    mlock_t v = mlock.load(std::memory_order_relaxed);
    while (true) {
        if (v >= mlock_t(-2)) {
            current()->yield();
            v = mlock.load(std::memory_order_relaxed);
        } else if (mlock.compare_exchange_weak(v, v + 1,
                                               std::memory_order_acquire)) {
            return;
        } else {
            // `compare_exchange_weak` already reloaded `v`
            pause();
        }
    }
}

void inode::unlock_read() {
    mlock_t v = mlock.load(std::memory_order_relaxed);
    assert(v != 0 && v != mlock_t(-1));
    while (!mlock.compare_exchange_weak(v, v - 1,
                                        std::memory_order_release)) {
        pause();
    }
}

void inode::lock_write() {
    mlock_t v = 0;
    while (!mlock.compare_exchange_weak(v, mlock_t(-1),
                                        std::memory_order_acquire)) {
        current()->yield();
        v = 0;
    }
}

void inode::unlock_write() {
    assert(has_write_lock());
    mlock.store(0, std::memory_order_release);
}

bool inode::has_write_lock() const {
    return mlock.load(std::memory_order_relaxed) == mlock_t(-1);
}

}


// chickadeefs state

chkfsstate chkfsstate::fs;

chkfsstate::chkfsstate() {
}


// clean_inode_block(entry)
//    Called when loading an inode block into the buffer cache. It clears
//    values that are only used in memory.

static void clean_inode_block(bcentry* entry) {
    log_printf("cleaning block for %d\n", entry->index());
    uint32_t entry_index = entry->index();
    auto is = reinterpret_cast<chkfs::inode*>(entry->buf_);
    for (unsigned i = 0; i != chkfs::inodesperblock; ++i) {
        // inode is initially unlocked
        is[i].mlock = 0;
        // containing entry's buffer cache position is `entry_index`
        is[i].mbcindex = entry_index;
    }
}


// chkfsstate::get_inode(inum)
//    Returns inode number `inum`, or `nullptr` if there's no such inode.
//    Obtains a reference on the buffer cache block containing the inode;
//    you should eventually release this reference by calling `ino->put()`.

chkfs::inode* chkfsstate::get_inode(inum_t inum) {
    auto& bc = bufcache::get();
    auto superblock_entry = bc.get_disk_entry(0);
    assert(superblock_entry);
    auto& sb = *reinterpret_cast<chkfs::superblock*>
        (&superblock_entry->buf_[chkfs::superblock_offset]);
    superblock_entry->put();

    chkfs::inode* ino = nullptr;
    if (inum > 0 && inum < sb.ninodes) {
        auto bn = sb.inode_bn + inum / chkfs::inodesperblock;
        if (auto inode_entry = bc.get_disk_entry(bn, clean_inode_block)) {
            ino = reinterpret_cast<inode*>(inode_entry->buf_);
            ino->entry();
        }
    }
    if (ino != nullptr) {
        ino += inum % chkfs::inodesperblock;
    }
    return ino;
}

namespace chkfs {
// chkfs::inode::entry()
//    Returns a pointer to the buffer cache entry containing this inode.
//    Requires that this inode is a pointer into buffer cache data.
bcentry* inode::entry() {
    assert(mbcindex < bufcache::ne);
    auto entry = &bufcache::get().e_[mbcindex];
    assert(entry->contains(this));
    return entry;
}

// chkfs::inode::put()
//    Releases the caller???s reference to this inode, which must be located
//    in the buffer cache.
void inode::put() {
    entry()->put();
}
}


// chkfsstate::lookup_inode(dirino, filename)
//    Looks up `filename` in the directory inode `dirino`, returning the
//    corresponding inode (or nullptr if not found). The caller must have
//    a read lock on `dirino`. The returned inode has a reference that
//    the caller should eventually release with `ino->put()`.

// chkfs::inode* chkfsstate::lookup_inode(inode* dirino,
//                                             const char* filename) {
//     return lookup_relative_inode_for_type(dirino, filename, chkfs::type_regular);
// }

chkfs::inode* chkfsstate::lookup_relative_inode_for_type(inode* dirino, const char* directory_name, int inode_type) {
    chkfs_fileiter it(dirino);

    // read directory to find file inode
    chkfs::inum_t in = 0;
    for (size_t diroff = 0; !in; diroff += blocksize) {
        if (bcentry* e = it.find(diroff).get_disk_entry()) {
            size_t bsz = min(dirino->size - diroff, blocksize);
            auto dirent = reinterpret_cast<chkfs::dirent*>(e->buf_);
            for (unsigned i = 0; i * sizeof(*dirent) < bsz; ++i, ++dirent) {
                if (dirent->inum && strcmp(dirent->name, directory_name) == 0) {
                    inode* file_inode = get_inode(dirent->inum);
                    if (file_inode->type == inode_type) {
                        in = dirent->inum;
                        file_inode->put();
                        break;
                    }
                    file_inode->put();
                }
            }
            e->put();
        } else {
            return nullptr;
        }
    }
    return get_inode(in);
}

chkfs::inode* chkfsstate::lookup_relative_directory_inode(inode* dirino, const char* directory_name) {
    return lookup_relative_inode_for_type(dirino, directory_name, chkfs::type_directory);
}

chkfs::inode* chkfsstate::lookup_relative_directory_inode(const char* directory_name) {
    auto dirino = get_inode(1);
    if (dirino) {
        dirino->lock_read();
        auto ino = fs.lookup_relative_directory_inode(dirino, directory_name);
        dirino->unlock_read();
        dirino->put();
        return ino;
    } else {
        return nullptr;
    }
}

chkfs::inode* chkfsstate::lookup_directory_inode(const char* directory_name) {
    path_elements path(directory_name);
    chkfs::inode* dirino = lookup_containing_directory_inode(directory_name);
    if (!dirino) {
        return nullptr;
    }
    dirino->lock_read();
    chkfs::inode* directory_inode = lookup_relative_directory_inode(dirino, path.last());
    dirino->unlock_read();
    dirino->put();
    return directory_inode;
}

// chkfsstate::lookup_inode(filename)
//    Looks up `filename` in the root directory.

// chkfs::inode* chkfsstate::lookup_inode(const char* filename) {
//     auto dirino = get_inode(1);
//     if (dirino) {
//         dirino->lock_read();
//         auto ino = fs.lookup_inode(dirino, filename);
//         dirino->unlock_read();
//         dirino->put();
//         return ino;
//     } else {
//         return nullptr;
//     }
// }


chkfs::inode* chkfsstate::lookup_containing_directory_inode(const char* filename) {
    path_elements path(filename);
    chkfs::inode* dirino = get_inode(1);
    assert(dirino);
    for (int i = 0; i < path.depth() - 1; i++) {
        dirino->lock_read();
        chkfs::inode* next_dirino = lookup_relative_directory_inode(dirino, path[i]);
        dirino->unlock_read();
        dirino->put();
        dirino = next_dirino;
        if (!dirino) {
            break;
        }
    }
    return dirino;
}

chkfs::inode* chkfsstate::lookup_relative_file_inode(inode* dirino,
                                            const char* filename) {
    return lookup_relative_inode_for_type(dirino, filename, chkfs::type_regular);
}

chkfs::inode* chkfsstate::lookup_file_inode(const char* filename) {
    path_elements path(filename);
    chkfs::inode* dirino = lookup_containing_directory_inode(filename);
    if (!dirino) {
        return nullptr;
    }
    dirino->lock_read();
    chkfs::inode* file_inode = lookup_relative_file_inode(dirino, path.last());
    dirino->unlock_read();
    dirino->put();
    return file_inode;
}

chkfs::inum_t chkfsstate::create_inode(int inode_type) {
    auto& bc = bufcache::get();
    auto superblock_entry = bc.get_disk_entry(0);
    assert(superblock_entry);
    auto& sb = *reinterpret_cast<chkfs::superblock*>
        (&superblock_entry->buf_[chkfs::superblock_offset]);
    superblock_entry->put();

    int ninode_blocks = sb.ninodes / chkfs::inodesperblock;
    inum_t inum = 0;
    for (int i = 0; i < ninode_blocks; i++) {
        auto bn = sb.inode_bn + i;

        if (auto inode_entry = bc.get_disk_entry(bn, clean_inode_block)) {
            chkfs::inode* ino = reinterpret_cast<inode*>(inode_entry->buf_);
            for (size_t j = 0; j < chkfs::inodesperblock; j++) {
                inum_t potential_inum = i * chkfs::inodesperblock + j;
                if (ino[j].type == 0 && potential_inum != 0 && potential_inum != 1) {
                    inode_entry->get_write();
                    inum = potential_inum;
                    ino[j].type = inode_type;
                    ino[j].nlink = 1;
                    ino[j].size = 0;
                    inode_entry->put_write();
                    break;
                }
            }
            inode_entry->put();
            if (inum > 0) {
                break;
            }
        } else {
            log_printf("create_inode failed \n");
            assert(false);
            return 0;
        }
    }

    assert(inum > 0);
    return inum;
}

int chkfsstate::create_dirent(inode* dirino, const char* filename, inum_t inum) {
    chkfs_fileiter it(dirino);
    for (size_t diroff = 0; ; diroff += blocksize) {
        if (it.find(diroff).empty()) {
            blocknum_t bn = fs.allocate_extent(1);
            if (bn >= chkfs::blocknum_t(E_MINERROR)) {
                return int(bn);
            }
            int res = it.find(diroff).insert(bn, 1);
            it.inode()->entry()->get_write();
            dirino->size += blocksize;
            it.inode()->entry()->put_write();
        }
        if (bcentry* e = it.find(diroff).get_disk_entry()) {
            size_t bsz = min(dirino->size - diroff, blocksize);
            auto dirent = reinterpret_cast<chkfs::dirent*>(e->buf_);
            for (unsigned i = 0; i * sizeof(*dirent) < bsz; ++i, ++dirent) {
                if (dirent->inum == 0) {
                    e->get_write();
                    dirent->inum = inum;
                    memcpy(&dirent->name, filename, strlen(filename) + 1);
                    e->put_write();
                    e->put();
                    return 1;
                }
            }
            e->put();
        } else {
            assert(false);
            log_printf("failing\n");
            return -1;
        }
    }
    return 1;
}

int chkfsstate::remove_dirent(inode* dirino, const char* filename, inum_t inum) {
    chkfs_fileiter it(dirino);
    for (size_t diroff = 0; ; diroff += blocksize) {
        if (!it.find(diroff).empty()) {
            bcentry* e = it.find(diroff).get_disk_entry();
            if (!e) {
                return E_NOSPC;
            }
            size_t bsz = min(dirino->size - diroff, blocksize);
            auto dirent = reinterpret_cast<chkfs::dirent*>(e->buf_);
            e->get_write();
            for (unsigned i = 0; i * sizeof(*dirent) < bsz; ++i, ++dirent) {
                
                if (dirent->inum == inum && strcmp(dirent->name, filename) == 0) {
                    log_printf("removing dirent for %s\n", dirent->name);
                    dirent->inum = 0;
                    dirent->name[0] = '\0';
                    e->put_write();
                    e->put();
                    return 1;
                }
            }
            e->put_write();
            e->put();
        } else {
            break;
        }
    }
    return 0;
}


chkfs::inode* chkfsstate::create_file_in_root_directory(const char* filename) {
    inum_t inum = create_inode(chkfs::type_regular);

    auto dirino = get_inode(1);
    if (dirino) {
        dirino->lock_write();
        int result = fs.create_dirent(dirino, filename, inum);
        dirino->unlock_write();
        dirino->put();
        return get_inode(inum);
    } else {
        return nullptr;
    }
}

chkfs::inode* chkfsstate::create_file_in_directory(chkfs::inode* dirino, const char* filename) {
    inum_t inum = create_inode(chkfs::type_regular);

    int result = fs.create_dirent(dirino, filename, inum);

    return get_inode(inum);
}

int chkfsstate::is_directory_empty(chkfs::inode* dirino) {
    chkfs_fileiter it(dirino);
    for (size_t diroff = 0; ; diroff += blocksize) {
        if (!it.find(diroff).empty()) {
            bcentry* e = it.find(diroff).get_disk_entry();
            if (!e) {
                return E_NOSPC;
            }
            size_t bsz = min(dirino->size - diroff, blocksize);
            auto dirent = reinterpret_cast<chkfs::dirent*>(e->buf_);
            for (unsigned i = 0; i * sizeof(*dirent) < bsz; ++i, ++dirent) {
                if (dirent->inum != 0) {
                    e->put();
                    return 0;
                }
            }
            e->put();
        } else {
            break;
        }
    }
    return 1;
}

// chkfsstate::allocate_extent(unsigned count)
//    Allocates and returns the first block number of a fresh extent.
//    The returned extent doesn't need to be initialized (but it should not be
//    in flight to the disk or part of any incomplete journal transaction).
//    Returns the block number of the first block in the extent, or an error
//    code on failure. Errors can be distinguished by
//    `blocknum >= blocknum_t(E_MINERROR)`.

auto chkfsstate::allocate_extent(unsigned count) -> blocknum_t {
    auto& bc = bufcache::get();
    auto superblock_entry = bc.get_disk_entry(0);
    assert(superblock_entry);
    auto& sb = *reinterpret_cast<chkfs::superblock*>
        (&superblock_entry->buf_[chkfs::superblock_offset]);
    superblock_entry->put();

    bcentry* fbb_b = bc.get_disk_entry(sb.fbb_bn);

    fbb_b->get_write();

    bitset_view fbb_bitset(reinterpret_cast<uint64_t*>(fbb_b->buf_), chkfs::bitsperblock);
    
    size_t contiguous_bit_start = fbb_bitset.find_x_contiguous_bits(count);

    if (contiguous_bit_start == size_t(-1)) {
        fbb_b->put_write();
        return E_NOSPC;
    }

    for (size_t i = 0; i < count; i++) {
        assert(fbb_bitset[contiguous_bit_start + i] == 1);
        fbb_bitset[contiguous_bit_start + i] = 0;
    }

    fbb_b->put_write();
    
    return contiguous_bit_start;
}

int chkfsstate::deallocate_extent(blocknum_t bn, unsigned count) {
        auto& bc = bufcache::get();
    auto superblock_entry = bc.get_disk_entry(0);
    assert(superblock_entry);
    auto& sb = *reinterpret_cast<chkfs::superblock*>
        (&superblock_entry->buf_[chkfs::superblock_offset]);
    superblock_entry->put();

    bcentry* fbb_b = bc.get_disk_entry(sb.fbb_bn);
    if (!fbb_b) {
        return E_NOSPC;
    }
    
    fbb_b->get_write();

    bitset_view fbb_bitset(reinterpret_cast<uint64_t*>(fbb_b->buf_), chkfs::bitsperblock);
    for (size_t i = bn; i < bn + count; i++) {
        assert(fbb_bitset[i] == 0);
        fbb_bitset[i] = 1;
    }

    fbb_b->put_write();
    return 0;
}

// inode_loader functions

ssize_t inode_loader::get_page(uint8_t** pg, size_t off) {
    if (!inode_) {
        return E_NOENT;
    } else if (off >= inode_->size) {
        return 0;
    } else {
        inode_->lock_read();
        chkfs_fileiter it(inode_);

        if (bcentry_ = it.find(off).get_disk_entry()) {
            unsigned b = it.block_relative_offset();
            *pg = bcentry_->buf_ + b;
            
            inode_->unlock_read();
            return size_t(chkfs::blocksize - b);
        } else {
            inode_->unlock_read();
            return -1;
        }
    }
}

void inode_loader::put_page() {
    if (bcentry_) {
        bcentry_->put();
    }
}

inode_vnode::inode_vnode(chkfs::inode* underlying_inode)
    : inode_(underlying_inode) {
}

ssize_t inode_vnode::read(char* buf, size_t sz, size_t offset) {
    inode_->lock_read();
    chkfs_fileiter it(inode_);

    size_t read_bytes = 0;


    log_printf("starting read %zu\n", inode_->size);
    while (read_bytes < sz && offset + read_bytes < inode_->size) {
        bcentry* b = it.find(offset + read_bytes).get_disk_entry();
        bufcache::get().prefetch(it.find(offset + read_bytes).blocknum() + 1, 4);
        if (!b) {
            inode_->unlock_read();
            return -1;
        }
        size_t block_offset = it.block_relative_offset();
        size_t to_read = min(inode_->size - read_bytes - offset, sz - read_bytes, size_t(chkfs::blocksize - block_offset));
        memcpy(buf + read_bytes, b->buf_ + block_offset, to_read);
        read_bytes += to_read;
        b->put();
    }
    
    inode_->unlock_read();
    return read_bytes;
}

ssize_t inode_vnode::write(char* buf, size_t sz, size_t offset) {
    inode_->lock_write();

    chkfs_fileiter it(inode_);

    size_t written_bytes = 0;
    while (written_bytes < sz) {
        if (it.find(offset + written_bytes).empty()) {
            size_t blocks_needed = round_up(sz - written_bytes, chkfs::blocksize) / chkfs::blocksize;
            auto& chkfs = chkfsstate::get();
            chkfs::blocknum_t bn = chkfs.allocate_extent(blocks_needed);
            if (bn >= chkfs::blocknum_t(E_MINERROR)) {
                return int(bn);
            }
            int res = it.find(offset + written_bytes).insert(bn, blocks_needed);
            assert(res == 0);
        }
        bcentry* b = it.find(offset + written_bytes).get_disk_entry();
        if (!b) {
            return E_NOSPC;
        }

        b->get_write();
        size_t block_offset = it.block_relative_offset();
        size_t to_write = min(sz - written_bytes, size_t(chkfs::blocksize - block_offset));
        memcpy(b->buf_ + block_offset, buf + written_bytes, to_write);
        written_bytes += to_write;
        b->put_write();
        b->put();
    }

    if (offset + written_bytes > inode_->size) {
        bcentry* b = inode_->entry();
        b->get_write();
        inode_->size = offset + written_bytes;
        b->put_write();
    }

    inode_->unlock_write();
    return written_bytes;
}

void inode_vnode::truncate() {
    inode_->lock_write();
    bcentry* b = inode_->entry();
    // marks block as dirty
    b->get_write();
    inode_->size = 0;
    b->put_write();
    
    inode_->unlock_write();
}


ssize_t inode_vnode::lseek(off_t offset, uint64_t flag, size_t current_offset) {
    inode_->lock_read();
    if (flag == LSEEK_SIZE) {
        inode_->unlock_read();
        return inode_->size;
    }
    ssize_t new_offset = current_offset;
    switch (flag) {
        case LSEEK_SET:
            new_offset = offset;
            break;
        case LSEEK_CUR:
            new_offset = ((ssize_t) current_offset) + offset;
            break;
        case LSEEK_END:
            new_offset = ((ssize_t) inode_->size) + offset;
            break;
    }

    inode_->unlock_read();

    if (new_offset < 0 || new_offset > inode_->size) {
        return E_INVAL;
    }

    return new_offset;
}

void inode_vnode::close() {
    inode_->put();
}
