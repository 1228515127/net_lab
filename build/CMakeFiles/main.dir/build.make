# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lsd/net_lab

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lsd/net_lab/build

# Include any dependencies generated for this target.
include CMakeFiles/main.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/main.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/main.dir/flags.make

CMakeFiles/main.dir/src/arp.c.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/arp.c.o: ../src/arp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/main.dir/src/arp.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/main.dir/src/arp.c.o   -c /home/lsd/net_lab/src/arp.c

CMakeFiles/main.dir/src/arp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/arp.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lsd/net_lab/src/arp.c > CMakeFiles/main.dir/src/arp.c.i

CMakeFiles/main.dir/src/arp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/arp.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lsd/net_lab/src/arp.c -o CMakeFiles/main.dir/src/arp.c.s

CMakeFiles/main.dir/src/driver.c.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/driver.c.o: ../src/driver.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/main.dir/src/driver.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/main.dir/src/driver.c.o   -c /home/lsd/net_lab/src/driver.c

CMakeFiles/main.dir/src/driver.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/driver.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lsd/net_lab/src/driver.c > CMakeFiles/main.dir/src/driver.c.i

CMakeFiles/main.dir/src/driver.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/driver.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lsd/net_lab/src/driver.c -o CMakeFiles/main.dir/src/driver.c.s

CMakeFiles/main.dir/src/ethernet.c.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/ethernet.c.o: ../src/ethernet.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/main.dir/src/ethernet.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/main.dir/src/ethernet.c.o   -c /home/lsd/net_lab/src/ethernet.c

CMakeFiles/main.dir/src/ethernet.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/ethernet.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lsd/net_lab/src/ethernet.c > CMakeFiles/main.dir/src/ethernet.c.i

CMakeFiles/main.dir/src/ethernet.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/ethernet.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lsd/net_lab/src/ethernet.c -o CMakeFiles/main.dir/src/ethernet.c.s

CMakeFiles/main.dir/src/icmp.c.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/icmp.c.o: ../src/icmp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/main.dir/src/icmp.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/main.dir/src/icmp.c.o   -c /home/lsd/net_lab/src/icmp.c

CMakeFiles/main.dir/src/icmp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/icmp.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lsd/net_lab/src/icmp.c > CMakeFiles/main.dir/src/icmp.c.i

CMakeFiles/main.dir/src/icmp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/icmp.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lsd/net_lab/src/icmp.c -o CMakeFiles/main.dir/src/icmp.c.s

CMakeFiles/main.dir/src/ip.c.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/ip.c.o: ../src/ip.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/main.dir/src/ip.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/main.dir/src/ip.c.o   -c /home/lsd/net_lab/src/ip.c

CMakeFiles/main.dir/src/ip.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/ip.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lsd/net_lab/src/ip.c > CMakeFiles/main.dir/src/ip.c.i

CMakeFiles/main.dir/src/ip.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/ip.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lsd/net_lab/src/ip.c -o CMakeFiles/main.dir/src/ip.c.s

CMakeFiles/main.dir/src/main.c.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/main.c.o: ../src/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/main.dir/src/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/main.dir/src/main.c.o   -c /home/lsd/net_lab/src/main.c

CMakeFiles/main.dir/src/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lsd/net_lab/src/main.c > CMakeFiles/main.dir/src/main.c.i

CMakeFiles/main.dir/src/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lsd/net_lab/src/main.c -o CMakeFiles/main.dir/src/main.c.s

CMakeFiles/main.dir/src/net.c.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/net.c.o: ../src/net.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/main.dir/src/net.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/main.dir/src/net.c.o   -c /home/lsd/net_lab/src/net.c

CMakeFiles/main.dir/src/net.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/net.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lsd/net_lab/src/net.c > CMakeFiles/main.dir/src/net.c.i

CMakeFiles/main.dir/src/net.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/net.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lsd/net_lab/src/net.c -o CMakeFiles/main.dir/src/net.c.s

CMakeFiles/main.dir/src/udp.c.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/udp.c.o: ../src/udp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/main.dir/src/udp.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/main.dir/src/udp.c.o   -c /home/lsd/net_lab/src/udp.c

CMakeFiles/main.dir/src/udp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/udp.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lsd/net_lab/src/udp.c > CMakeFiles/main.dir/src/udp.c.i

CMakeFiles/main.dir/src/udp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/udp.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lsd/net_lab/src/udp.c -o CMakeFiles/main.dir/src/udp.c.s

CMakeFiles/main.dir/src/utils.c.o: CMakeFiles/main.dir/flags.make
CMakeFiles/main.dir/src/utils.c.o: ../src/utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/main.dir/src/utils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/main.dir/src/utils.c.o   -c /home/lsd/net_lab/src/utils.c

CMakeFiles/main.dir/src/utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/main.dir/src/utils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lsd/net_lab/src/utils.c > CMakeFiles/main.dir/src/utils.c.i

CMakeFiles/main.dir/src/utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/main.dir/src/utils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lsd/net_lab/src/utils.c -o CMakeFiles/main.dir/src/utils.c.s

# Object files for target main
main_OBJECTS = \
"CMakeFiles/main.dir/src/arp.c.o" \
"CMakeFiles/main.dir/src/driver.c.o" \
"CMakeFiles/main.dir/src/ethernet.c.o" \
"CMakeFiles/main.dir/src/icmp.c.o" \
"CMakeFiles/main.dir/src/ip.c.o" \
"CMakeFiles/main.dir/src/main.c.o" \
"CMakeFiles/main.dir/src/net.c.o" \
"CMakeFiles/main.dir/src/udp.c.o" \
"CMakeFiles/main.dir/src/utils.c.o"

# External object files for target main
main_EXTERNAL_OBJECTS =

../test/main: CMakeFiles/main.dir/src/arp.c.o
../test/main: CMakeFiles/main.dir/src/driver.c.o
../test/main: CMakeFiles/main.dir/src/ethernet.c.o
../test/main: CMakeFiles/main.dir/src/icmp.c.o
../test/main: CMakeFiles/main.dir/src/ip.c.o
../test/main: CMakeFiles/main.dir/src/main.c.o
../test/main: CMakeFiles/main.dir/src/net.c.o
../test/main: CMakeFiles/main.dir/src/udp.c.o
../test/main: CMakeFiles/main.dir/src/utils.c.o
../test/main: CMakeFiles/main.dir/build.make
../test/main: CMakeFiles/main.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lsd/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Linking C executable ../test/main"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/main.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/main.dir/build: ../test/main

.PHONY : CMakeFiles/main.dir/build

CMakeFiles/main.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/main.dir/cmake_clean.cmake
.PHONY : CMakeFiles/main.dir/clean

CMakeFiles/main.dir/depend:
	cd /home/lsd/net_lab/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lsd/net_lab /home/lsd/net_lab /home/lsd/net_lab/build /home/lsd/net_lab/build /home/lsd/net_lab/build/CMakeFiles/main.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/main.dir/depend

