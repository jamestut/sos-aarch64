#
# Copyright 2019, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the GNU General Public License version 2. Note that NO WARRANTY is provided.
# See "LICENSE_GPLv2.txt" for details.
#
# @TAG(DATA61_GPL)
#
project(sos C)

set(configure_string "")

config_string(SosNFSDir SOS_NFS_DIR "NFS directory" DEFAULT "/export/odroid")

config_string(SosGateway SOS_GATEWAY "Gateway IP address" DEFAULT "192.168.168.1")

config_string(SosFrameLimit SOS_FRAME_LIMIT "Frame table frame limit" UNQUOTE DEFAULT "0ul")

config_string(SosUseFakePageFile SOS_FAKE_PF "Use fake page file" UNQUOTE DEFAULT "0ul")

config_string(SosUseLocalFS SOS_LOCAL_FS "Use local FS on CPIO instead of NFS" UNQUOTE DEFAULT "0ul")

config_string(SosMaxPID SOS_MAX_PID "Maximum number of processes that can run at the same time" UNQUOTE DEFAULT "128ul")

config_string(SosExtraThreads SOS_EXTRA_THREADS "Additional number of internal threads supported beyond those used for user processes" UNQUOTE DEFAULT "8ul")

config_string(SosIntThreadsStackPages SOS_INT_THREADS_STACK_PAGES "Number of pages for each internal SOS stack" UNQUOTE DEFAULT "2ul")

config_string(SosMaxFileName SOS_MAX_FILENAME "Maximum length of filename plus one" UNQUOTE DEFAULT "4096ul")

add_config_library(sos "${configure_string}")

# warn about everything
add_compile_options(-Wall -W -Wextra)
# enable stack unwind tables -- this allows backtrace() to work.
add_compile_options(-funwind-tables)
add_definitions(-DSTDSOCKET)
add_definitions(-U__linux__)
add_definitions(-D_SYS_POLL_H)

# list of apps to include in the cpio archive
if(NOT SosDisableCPIO)
    get_property(apps GLOBAL PROPERTY apps_property)
endif()
MakeCPIO(archive.o "${apps}")

# add any new c files here
add_executable(
    sos
    EXCLUDE_FROM_ALL
    src/bootstrap.c
    src/dma.c
    src/elf.c
    src/frame_table.c
    src/irq.c
    src/main.c
    src/mapping.c
    src/network.c
    src/ut.c
    src/tests.c
    src/sys/backtrace.c
    src/sys/exit.c
    src/sys/morecore.c
    src/sys/stdio.c
    src/sys/thread.c
    src/sys/time.c
    src/drivers/uart.c
    archive.o
    src/sos.lds
    src/utils.c
    src/threads.c
    # GRP01: M1
    src/fakes/timer.c
    # GRP01: M2
    src/bgworker.c
    src/fileman.c
    src/fs/nullfile.c
    src/fs/console.c
    src/timesyscall.c
    # GRP01: M3
    src/vm/mapping2.c
    src/vm/addrspace.c
    src/vm/syshandlers.c
    src/vm/faulthandler.c
    # GRP01: M4
    src/delegate.c
    src/fs/nfs.c
    src/fs/fake.c
    # GRP01: re-arch
    src/proctable.c
    # GRP01: qemu
    src/fs/pl011console.c
    src/fs/cpiofs.c
    # GRP01: M6
    src/procman.c
    src/procsyscall.c
)
target_include_directories(sos PRIVATE "include" "../libsosapi/include")
target_link_libraries(
    sos
    sel4_autoconf
    sel4runtime
    muslc
    sel4
    elf
    cpio
    serial
    clock
    sel4cspace
    aos
    utils
    picotcp
    picotcp_bsd
    nfs
    ethernet
    sel4sync
    sos_Config
    grp01util
)

set_property(
    TARGET sos
    APPEND_STRING
    PROPERTY LINK_FLAGS " -T ${CMAKE_CURRENT_SOURCE_DIR}/src/sos.lds "
)
# Set this image as the rootserver
DeclareRootserver(sos)
