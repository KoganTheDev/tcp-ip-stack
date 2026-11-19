#pragma once

#include <cstdint>

// The stateful harness (fuzz/stack.cpp) fixes the stack's secrets with this
// seed (NetworkStack::set_secret_seed()), so its connection's ISN and
// timestamp clock are the same on every run: an input then means the same
// thing every time it is replayed, and the corpus generator can build seeds
// that acknowledge the connection's real sequence numbers (forged D-SACKs,
// for one) instead of being rejected as out of window.
constexpr uint64_t STACK_HARNESS_SECRET_SEED = 0x5eedf00dULL;
