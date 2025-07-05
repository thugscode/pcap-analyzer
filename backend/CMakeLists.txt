cmake_minimum_required(VERSION 3.10)
project(pcap_analyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Include directories
include_directories(${PCAP_INCLUDE_DIRS})

# Add external dependencies
# Crow is header-only, so we just need to include it
include_directories(external/crow/include)

# Add nlohmann/json
include_directories(external/json/single_include)

# Add the executable
add_executable(pcap_analyzer main.cpp)

# Link libraries
target_link_libraries(pcap_analyzer ${PCAP_LIBRARIES} pthread)