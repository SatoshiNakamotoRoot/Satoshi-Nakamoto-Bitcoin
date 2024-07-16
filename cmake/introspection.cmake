# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

include(CheckCXXSourceCompiles)
include(CheckCXXSymbolExists)
include(CheckIncludeFileCXX)

# The following HAVE_{HEADER}_H variables go to the bitcoin-config.h header.
check_include_file_cxx(sys/prctl.h HAVE_SYS_PRCTL_H)
check_include_file_cxx(sys/resources.h HAVE_SYS_RESOURCES_H)
check_include_file_cxx(sys/vmmeter.h HAVE_SYS_VMMETER_H)
check_include_file_cxx(vm/vm_param.h HAVE_VM_VM_PARAM_H)

check_cxx_symbol_exists(O_CLOEXEC "fcntl.h" HAVE_O_CLOEXEC)

check_include_file_cxx(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
  check_cxx_symbol_exists(fdatasync "unistd.h" HAVE_FDATASYNC)
  check_cxx_symbol_exists(fork "unistd.h" HAVE_DECL_FORK)
  check_cxx_symbol_exists(pipe2 "unistd.h" HAVE_DECL_PIPE2)
  check_cxx_symbol_exists(setsid "unistd.h" HAVE_DECL_SETSID)
endif()

check_include_file_cxx(sys/types.h HAVE_SYS_TYPES_H)
check_include_file_cxx(ifaddrs.h HAVE_IFADDRS_H)
if(HAVE_SYS_TYPES_H AND HAVE_IFADDRS_H)
  include(TestAppendRequiredLibraries)
  test_append_socket_library(core_interface)
endif()

include(TestAppendRequiredLibraries)
test_append_atomic_library(core_interface)

check_cxx_symbol_exists(std::system "cstdlib" HAVE_STD_SYSTEM)
check_cxx_symbol_exists(::_wsystem "stdlib.h" HAVE__WSYSTEM)
if(HAVE_STD_SYSTEM OR HAVE__WSYSTEM)
  set(HAVE_SYSTEM 1)
endif()

check_include_file_cxx(string.h HAVE_STRING_H)
if(HAVE_STRING_H)
  check_cxx_source_compiles("
    #include <string.h>

    int main()
    {
      char buf[100];
      char* p{strerror_r(0, buf, sizeof buf)};
      (void)p;
    }
    " STRERROR_R_CHAR_P
  )
endif()

# Check for malloc_info (for memory statistics information in getmemoryinfo).
check_cxx_symbol_exists(malloc_info "malloc.h" HAVE_MALLOC_INFO)

# Check for mallopt(M_ARENA_MAX) (to set glibc arenas).
check_cxx_source_compiles("
  #include <malloc.h>

  int main()
  {
    mallopt(M_ARENA_MAX, 1);
  }
  " HAVE_MALLOPT_ARENA_MAX
)

# Check for posix_fallocate().
check_cxx_source_compiles("
  // same as in src/util/fs_helpers.cpp
  #ifdef __linux__
  #ifdef _POSIX_C_SOURCE
  #undef _POSIX_C_SOURCE
  #endif
  #define _POSIX_C_SOURCE 200112L
  #endif // __linux__
  #include <fcntl.h>

  int main()
  {
    return posix_fallocate(0, 0, 0);
  }
  " HAVE_POSIX_FALLOCATE
)

# Check for strong getauxval() support in the system headers.
check_cxx_source_compiles("
  #include <sys/auxv.h>

  int main()
  {
    getauxval(AT_HWCAP);
  }
  " HAVE_STRONG_GETAUXVAL
)

# Check for UNIX sockets.
check_cxx_source_compiles("
  #include <sys/socket.h>
  #include <sys/un.h>

  int main()
  {
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
  }
  " HAVE_SOCKADDR_UN
)

# Check for different ways of gathering OS randomness:
# - Linux getrandom()
check_cxx_source_compiles("
  #include <sys/random.h>

  int main()
  {
    getrandom(nullptr, 32, 0);
  }
  " HAVE_GETRANDOM
)

# - BSD getentropy()
check_cxx_source_compiles("
  #include <sys/random.h>

  int main()
  {
    getentropy(nullptr, 32);
  }
  " HAVE_GETENTROPY_RAND
)


# - BSD sysctl()
check_cxx_source_compiles("
  #include <sys/types.h>
  #include <sys/sysctl.h>

  #ifdef __linux__
  #error Don't use sysctl on Linux, it's deprecated even when it works
  #endif

  int main()
  {
    sysctl(nullptr, 2, nullptr, nullptr, nullptr, 0);
  }
  " HAVE_SYSCTL
)

# - BSD sysctl(KERN_ARND)
check_cxx_source_compiles("
  #include <sys/types.h>
  #include <sys/sysctl.h>

  #ifdef __linux__
  #error Don't use sysctl on Linux, it's deprecated even when it works
  #endif

  int main()
  {
    static int name[2] = {CTL_KERN, KERN_ARND};
    sysctl(name, 2, nullptr, nullptr, nullptr, 0);
  }
  " HAVE_SYSCTL_ARND
)

check_cxx_source_compiles("
  int foo(void) __attribute__((visibility(\"default\")));
  int main(){}
  " HAVE_DEFAULT_VISIBILITY_ATTRIBUTE
)

check_cxx_source_compiles("
  __declspec(dllexport) int foo(void);
  int main(){}
  " HAVE_DLLEXPORT_ATTRIBUTE
)
