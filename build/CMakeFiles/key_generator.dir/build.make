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
include CMakeFiles/key_generator.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/key_generator.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/key_generator.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/key_generator.dir/flags.make

CMakeFiles/key_generator.dir/src/key_generator.cpp.o: CMakeFiles/key_generator.dir/flags.make
CMakeFiles/key_generator.dir/src/key_generator.cpp.o: /home/Code/24102801-ringSig/src/key_generator.cpp
CMakeFiles/key_generator.dir/src/key_generator.cpp.o: CMakeFiles/key_generator.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/Code/24102801-ringSig/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/key_generator.dir/src/key_generator.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/key_generator.dir/src/key_generator.cpp.o -MF CMakeFiles/key_generator.dir/src/key_generator.cpp.o.d -o CMakeFiles/key_generator.dir/src/key_generator.cpp.o -c /home/Code/24102801-ringSig/src/key_generator.cpp

CMakeFiles/key_generator.dir/src/key_generator.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/key_generator.dir/src/key_generator.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/Code/24102801-ringSig/src/key_generator.cpp > CMakeFiles/key_generator.dir/src/key_generator.cpp.i

CMakeFiles/key_generator.dir/src/key_generator.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/key_generator.dir/src/key_generator.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/Code/24102801-ringSig/src/key_generator.cpp -o CMakeFiles/key_generator.dir/src/key_generator.cpp.s

# Object files for target key_generator
key_generator_OBJECTS = \
"CMakeFiles/key_generator.dir/src/key_generator.cpp.o"

# External object files for target key_generator
key_generator_EXTERNAL_OBJECTS =

libkey_generator.a: CMakeFiles/key_generator.dir/src/key_generator.cpp.o
libkey_generator.a: CMakeFiles/key_generator.dir/build.make
libkey_generator.a: CMakeFiles/key_generator.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/Code/24102801-ringSig/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libkey_generator.a"
	$(CMAKE_COMMAND) -P CMakeFiles/key_generator.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/key_generator.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/key_generator.dir/build: libkey_generator.a
.PHONY : CMakeFiles/key_generator.dir/build

CMakeFiles/key_generator.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/key_generator.dir/cmake_clean.cmake
.PHONY : CMakeFiles/key_generator.dir/clean

CMakeFiles/key_generator.dir/depend:
	cd /home/Code/24102801-ringSig/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/Code/24102801-ringSig /home/Code/24102801-ringSig /home/Code/24102801-ringSig/build /home/Code/24102801-ringSig/build /home/Code/24102801-ringSig/build/CMakeFiles/key_generator.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/key_generator.dir/depend
