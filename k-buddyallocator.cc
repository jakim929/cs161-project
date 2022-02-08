#include "kernel.hh"

// buddyallocator::buddyallocator()
//    The constructor initializes the `buddyallocator` to empty.

buddyallocator::buddyallocator() {
}

void buddyallocator::init() {
  // Assert that this is initialized to 0 / null;
  for (size_t i = 0; i < MEMSIZE_PHYSICAL / PAGESIZE; i++) {
    assert(pages_[i].order == 0);
    assert(!pages_[i].is_free);
    assert(pages_[i].link_.next_ == nullptr);
    assert(pages_[i].link_.prev_ == nullptr);
    pages_[i].is_free = true;
  } 

  auto range = physical_ranges.find(0);
  while(range != physical_ranges.end()) {
      if (range->type() == mem_available) {
        init_range(range->first(), range->last());
      } else {
        init_reserved_range(range->first(), range->last());
      }
      ++range;
  }

  // for(int i = 0; i < max_order_ - min_order_; i++) {
  //   for (pagestatus* pg = free_lists_[i].front(); pg; pg = free_lists_[i].next(pg)) {
  //     log_printf("%p [%d]\n", (pg - pages_) * PAGESIZE, pg->order);
  //   }
  // }

  assert(&pages_[0xa000 / PAGESIZE] == free_lists_[1].back());
}

uintptr_t buddyallocator::allocate(size_t size) {
  int desired_order = get_desired_order(size);
  pagestatus* pg = find_smallest_free(desired_order);
  if (!pg) {
    for(int i = 0; i < max_order_ - min_order_; i++) {
      assert(free_lists_[i].empty());
    }
    log_printf("out of memory");
    assert(pg != nullptr);
    // Out of memory
  }

  pagestatus* split_page = split_to_order(pg, desired_order);

  split_page->is_free = false;
  split_page->link_.erase();
  return get_pa(split_page);
}

uintptr_t buddyallocator::free(uintptr_t addr) {
  
}

pagestatus* buddyallocator::split_to_order(pagestatus* pg, int order) {
  if (pg->order == order) {
    return pg;
  }
  assert(pg->order > order);
  assert(pg->is_free);
  assert(pg->order > min_order_);
  int page_id = pg - pages_ ;
  int buddy_id = find_buddy_id_for_order(page_id, pg->order - 1);
  
  assert((uintptr_t) buddy_id < MEMSIZE_PHYSICAL / PAGESIZE);

  pg->link_.erase();
  pg->order--;
  free_lists_[pg->order - min_order_].push_back(pg);

  pagestatus* buddy = &pages_[buddy_id];
  assert(!buddy->link_.is_linked());
  buddy->order = pg->order;
  buddy->is_free = true;
  free_lists_[buddy->order - min_order_].push_back(buddy);
  
  return split_to_order(buddy, order);
}

// // recursively merges as far up as possible
// void buddyallocator::merge(pagestatus* pg) {
//   assert(pg->is_free);
//   if (pg->order == max_order_) {
//     return;
//   }
//   int buddy_id = find_buddy_id(page_id);
//   // Has no buddy
//   if (buddy_id >= (MEMSIZE_PHYSICAL / PAGESIZE)) {
//     return;
//   }
//   if (!pages_[buddy_id].is_free) {
//     return;
//   }
  
//   pagestatus* buddy = &pages_[buddy_id];
//   pagestatus* page_start = buddy > page_start ? pg : buddy;
//   pagestatus* page_end = buddy > page_start ? buddy : pg;

//   pagestatus* merged = merge_buddies(page_start, page_end);
//   merge(merged);
// }

// pagestatus* buddyallocator::merge_buddies(pagestatus* buddy1, pagestatus* buddy2) {
//   assert(buddy1->is_free && buddy2->is_free);
//   assert(buddy1->order != 0);
//   assert(buddy1->order == buddy2->order);
//   buddy2->link_.erase();
//   buddy2->order = 0;
//   buddy1->order++;
//   free_lists_[buddy1->order - min_order_].push_back(buddy1);
//   return buddy1;
// }

int buddyallocator::find_buddy_id(int page_id) {
  return find_buddy_id_for_order(page_id, pages_[page_id].order);
}

int buddyallocator::find_buddy_id_for_order(int page_id, int order) {
  int offset = get_index_offset(order);
  int buddy_id = is_index_aligned(page_id, order + 1) ? (page_id + offset) : (page_id - offset);
  assert(buddy_id >= 0);
  return buddy_id;
}

bool buddyallocator::is_index_aligned(int page_id, int order) {
  return (page_id) % get_index_offset(order) == 0;
}

int buddyallocator::get_index_offset(int order) {
  return 1 << (order - (msb(PAGESIZE) -1));
}

int buddyallocator::get_page_index(pagestatus* pg) {
  return pg - pages_;
}

int buddyallocator::get_pa(pagestatus* pg) {
  return (pg - pages_) * PAGESIZE;
}

pagestatus* buddyallocator::find_smallest_free(int order) {
  pagestatus* pg = free_lists_[order - min_order_].back();
  if (pg) {
    return pg;
  }
  if (order == max_order_) {
    return nullptr;
  }
  return find_smallest_free(order + 1);
}

int buddyallocator::get_desired_order(size_t size) {
  int min_order = msb(size - 1);
  assert(min_order <= max_order_);
  return max(min_order, min_order_);
}

void buddyallocator::init_range(uintptr_t start, uintptr_t end) {
  assert(start <= end);
  if (start == end) {
    return;
  }
  int max_order = max_order_allocable(start, end);
  pagestatus* pg = &pages_[start / PAGESIZE];
  pg->order = max_order;
  pg->is_free = true;
  pg->link_.reset();
  free_lists_[max_order - min_order_].push_back(pg);
  init_range(start + (1 << max_order), end);
}

void buddyallocator::init_reserved_range(uintptr_t start, uintptr_t end) {
  if (start > MEMSIZE_PHYSICAL || end > MEMSIZE_PHYSICAL) {
    return;
  }

  assert(start <= end);
  if (start == end) {
    return;
  }
  for (uintptr_t i = start / PAGESIZE; i < end  / PAGESIZE; i++) {
    pages_[i].is_free = false;
  }
}

int buddyallocator::max_order_allocable(uintptr_t start, uintptr_t end) {
  assert (end > start);
  int max_size_order = msb(end - start) - 1;
  assert(max_size_order >= min_order_);

  int max_aligned_order = lsb(start) - 1;
  assert(start % (1 << max_aligned_order) == 0);
  return min(max_size_order, max_aligned_order, max_order_);
}
