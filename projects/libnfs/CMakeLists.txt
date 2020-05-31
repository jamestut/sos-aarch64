#
# Copyright 2018, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the BSD 2-Clause license. Note that NO WARRANTY is provided.
# See "LICENSE_BSD2.txt" for details.
#
# @TAG(DATA61_BSD)
#

config_option(LibNfs LIB_NFS "Build libnfs" DEFAULT OFF)

if(LibNfs)
    set(HAVE_ARPA_INET_H 1)
    set(HAVE_CLOCK_GETTIME 1)
    set(HAVE_DLFCN_H 1)
    set(HAVE_FUSE_H 1)
    set(HAVE_INTTYPES_H 1)
    set(HAVE_MEMORY_H 1)
    set(HAVE_NETDB_H 1)
    set(HAVE_NETINET_IN_H 1)
    set(HAVE_NETINET_TCP_H 1)
    set(HAVE_NET_IF_H 1)
    set(HAVE_POLL_H 1)
    set(HAVE_SOCKADDR_STORAGE 1)
    set(HAVE_STDINT_H 1)
    set(HAVE_STDLIB_H 1)
    set(HAVE_STRINGS_H 1)
    set(HAVE_STRINGS_H 1)
    set(HAVE_STRING_H 1)
    set(HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC 1)
    set(HAVE_SYS_IOCTL_H 1)
    set(HAVE_SYS_SOCKET_H 1)
    set(HAVE_SYS_STATVFS_H 1)
    set(HAVE_SYS_STAT_H 1)
    set(HAVE_SYS_SYSMACROS_H 1)
    set(HAVE_SYS_TIME_H 1)
    set(HAVE_TIME_H 1)
    set(HAVE_SYS_TYPES_H 1)
    set(HAVE_SYS_VFS_H 1)
    set(HAVE_TALLOC_TEVENT 1)
    set(HAVE_UNISTD_H 1)
    set(HAVE_UTIME_H 1)

    link_libraries(muslc)
    # definitions to make the library compile with muslc
    add_definitions(-D__ANDROID__)
    add_definitions(-U__linux__)

    # find libnfs
    find_file(LIBNFS_PATH libnfs PATHS ${CMAKE_SOURCE_DIR} CMAKE_FIND_ROOT_PATH_BOTH)
    mark_as_advanced(FORCE LIBNFS_PATH)
    if("${LIBNFS_PATH}" STREQUAL "LIBNFS_PATH-NOTFOUND")
        message(FATAL_ERROR "Failed to find libnfs. Consider cmake -DLIBNFS_PATH=/path/to/libnfs")
    endif()

    add_subdirectory(${LIBNFS_PATH} ${CMAKE_BINARY_DIR}/libnfs)
endif()
