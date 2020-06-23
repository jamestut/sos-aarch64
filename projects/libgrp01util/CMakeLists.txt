cmake_minimum_required(VERSION 3.7.2)

project(libgrp01util C)

file(GLOB deps src/*.c)

list(SORT deps)

add_library(grp01util STATIC EXCLUDE_FROM_ALL ${deps})
target_include_directories(grp01util
    PUBLIC
        include
)
target_link_libraries(grp01util muslc utils sel4_autoconf)
