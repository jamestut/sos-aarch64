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
cmake_minimum_required(VERSION 3.7.2)

project(md5 C)

# warn about everything
add_compile_options(-Wall -g3 -O0)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -u __vsyscall_ptr")

add_executable(md5 EXCLUDE_FROM_ALL 
    src/md5.c
    src/main.c
    src/ttyout.c)
target_include_directories(md5 PRIVATE include)
target_link_libraries(md5 sel4runtime muslc sel4 sosapi)

add_app(md5)
