project(com.example.testclick)
cmake_minimum_required(VERSION 2.8.9)

# Standard install paths
include(GNUInstallDirs)

set(CMAKE_INSTALL_PREFIX /)
set(CMAKE_INSTALL_BINDIR /)
set(DATA_DIR /)

install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/bin/pycrash
	DESTINATION ${CMAKE_INSTALL_BINDIR})

add_subdirectory(click)
