# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.27

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/lib/python3.10/dist-packages/cmake/data/bin/cmake

# The command to remove a file.
RM = /usr/local/lib/python3.10/dist-packages/cmake/data/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/Code/24102801-ringSig

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/Code/24102801-ringSig/build

# Include any dependencies generated for this target.
include CMakeFiles/sign_test.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/sign_test.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/sign_test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sign_test.dir/flags.make

CMakeFiles/sign_test.dir/src/sign_test.cpp.o: CMakeFiles/sign_test.dir/flags.make
CMakeFiles/sign_test.dir/src/sign_test.cpp.o: /home/Code/24102801-ringSig/src/sign_test.cpp
CMakeFiles/sign_test.dir/src/sign_test.cpp.o: CMakeFiles/sign_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/Code/24102801-ringSig/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/sign_test.dir/src/sign_test.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/sign_test.dir/src/sign_test.cpp.o -MF CMakeFiles/sign_test.dir/src/sign_test.cpp.o.d -o CMakeFiles/sign_test.dir/src/sign_test.cpp.o -c /home/Code/24102801-ringSig/src/sign_test.cpp

CMakeFiles/sign_test.dir/src/sign_test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/sign_test.dir/src/sign_test.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/Code/24102801-ringSig/src/sign_test.cpp > CMakeFiles/sign_test.dir/src/sign_test.cpp.i

CMakeFiles/sign_test.dir/src/sign_test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/sign_test.dir/src/sign_test.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/Code/24102801-ringSig/src/sign_test.cpp -o CMakeFiles/sign_test.dir/src/sign_test.cpp.s

# Object files for target sign_test
sign_test_OBJECTS = \
"CMakeFiles/sign_test.dir/src/sign_test.cpp.o"

# External object files for target sign_test
sign_test_EXTERNAL_OBJECTS =

sign_test: CMakeFiles/sign_test.dir/src/sign_test.cpp.o
sign_test: CMakeFiles/sign_test.dir/build.make
sign_test: libsigner.a
sign_test: libkey_generator.a
sign_test: libhash.a
sign_test: /usr/lib/x86_64-linux-gnu/libcrypto.so
sign_test: CMakeFiles/sign_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/Code/24102801-ringSig/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable sign_test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sign_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sign_test.dir/build: sign_test
.PHONY : CMakeFiles/sign_test.dir/build

CMakeFiles/sign_test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sign_test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sign_test.dir/clean

CMakeFiles/sign_test.dir/depend:
	cd /home/Code/24102801-ringSig/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/Code/24102801-ringSig /home/Code/24102801-ringSig /home/Code/24102801-ringSig/build /home/Code/24102801-ringSig/build /home/Code/24102801-ringSig/build/CMakeFiles/sign_test.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/sign_test.dir/depend

