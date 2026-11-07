// Link workaround for a latent problem in src/, which this change is not
// allowed to touch.
//
// Bytes::append_int<T> is declared in bytes.h but DEFINED in utils.h. dns.cpp
// and dhcp_client.cpp call append_int<uint8_t> without including utils.h, so
// they emit an undefined reference and rely on some other translation unit
// having instantiated it. At -O0 with g++ one always happens to have, as a weak
// symbol. Under clang at -O1, or with g++ -O2, those instantiations are inlined
// away and the link fails with "undefined reference to
// Bytes::append_int<unsigned char>".
//
// Explicitly instantiating it here, in the binaries that need an optimised
// build (the fuzz and bench presets), makes them link. The proper fix is
// #include "utils.h" in the two src files (or an explicit instantiation in
// utils.cpp); it is reported rather than made here.

#include "utils.h"

template void Bytes::append_int<uint8_t>(uint8_t);
