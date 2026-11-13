# libFuzzer harnesses. Configured by the `fuzz` preset (clang only): the stack
# library is compiled with -fsanitize=fuzzer-no-link,address,undefined by the
# preset's CMAKE_CXX_FLAGS, which instruments it for coverage without giving it
# a main(); each harness then links the fuzzer runtime with -fsanitize=fuzzer.
# That split is why the flags are not simply "-fsanitize=fuzzer" everywhere:
# the library, the corpus generator and the harnesses are different binaries,
# and only the harnesses may carry libFuzzer's main().
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "TCPIP_BUILD_FUZZERS needs clang (libFuzzer); use the fuzz preset")
endif()

set(FUZZ_PARSERS ethernet ipv4 tcp udp icmp arp dhcp dns ipv6)
set(FUZZ_HARNESSES ${FUZZ_PARSERS} icmpv6 ip_reassembler stack)

foreach(name IN LISTS FUZZ_HARNESSES)
    set(sources ${PROJECT_SOURCE_DIR}/fuzz/${name}.cpp)
    # The stateful harness builds its handshake frames with the simulator's
    # frame builder, which is test code and lives under tests/.
    if(name STREQUAL "stack")
        list(APPEND sources ${PROJECT_SOURCE_DIR}/tests/src/sim_tcp_frame.cpp)
    endif()
    add_executable(fuzz_${name} ${sources})
    target_include_directories(fuzz_${name} PRIVATE
        ${PROJECT_SOURCE_DIR}/fuzz ${PROJECT_SOURCE_DIR}/tests/include)
    target_link_libraries(fuzz_${name} PRIVATE tcpip)
    target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer)
endforeach()

# Writes the seed corpus: frames built with the stack's own serializers, plus
# a few edge cases. Run by hand when the seeds should change (`make fuzz-seeds`);
# the result is committed, so a fuzz run never needs it.
add_executable(fuzz_gen_corpus ${PROJECT_SOURCE_DIR}/fuzz/gen_corpus.cpp
    ${PROJECT_SOURCE_DIR}/tests/src/sim_tcp_frame.cpp)
target_include_directories(fuzz_gen_corpus PRIVATE ${PROJECT_SOURCE_DIR}/tests/include)
target_link_libraries(fuzz_gen_corpus PRIVATE tcpip)
