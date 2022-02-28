#include "kernel.hh"
#include "k-wait.hh"

timingwheel::timingwheel() {
}

wait_queue* timingwheel::get_wq_for_time(uint64_t time) {
  return &wqs_[time % n_];
}

void timingwheel::wake_for_time(uint64_t time) {
  timer_queue.get_wq_for_time(ticks.load())->wake_all();
}

void timingwheel::wake_all() {
  for (int i = 0; i < n_; i++) {
    wqs_[i].wake_all();
  }
}
