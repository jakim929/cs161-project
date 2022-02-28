#include "kernel.hh"

timingwheel::timingwheel() {
}

wait_queue* timingwheel::get_wq_for_time(uint64_t time) {
  return &wqs_[time % n_];
}
