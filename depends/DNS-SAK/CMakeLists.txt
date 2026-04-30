# --- Basic project settings ---
cmake_minimum_required(VERSION 3.8)
project(DNS-SAK C)

# --- Global compile options ---
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
# set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

if(CMAKE_BUILD_TYPE STREQUAL Debug)
    add_compile_definitions(_DEBUG)
    message(STATUS "Build type: Debug (with _DEBUG definition)")
else()
    message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
endif()

add_compile_definitions(_USE_BINARYSEARCH)
add_compile_definitions(_GNU_SOURCE)

# --- Find dependency libraries ---
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)
pkg_check_modules(LIBPCAP REQUIRED libpcap)

# ==========================================================
#                  Core Library
# ==========================================================
# Use file(GLOB) to automatically find all .c files under utils/
file(GLOB CORE_SOURCES "utils/*.c")

add_library(dns_sak_core STATIC ${CORE_SOURCES})

# Set the include directory as public header directory
target_include_directories(dns_sak_core
    PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link dependencies for the core library and set them as PUBLIC
# so any target linking to dns_sak_core will automatically inherit these link and header paths
target_link_libraries(dns_sak_core
    PUBLIC
    ${CMAKE_THREAD_LIBS_INIT}
    ${LIBUV_LIBRARIES}
    ${LIBPCAP_LIBRARIES}
)
target_include_directories(dns_sak_core
    PUBLIC
    ${LIBUV_INCLUDE_DIRS}
    ${LIBPCAP_INCLUDE_DIRS}
)

# ==========================================================
#       Create executables from src directory
# ==========================================================
file(GLOB SRC_FILES "src/*.c")

foreach(SRC_FILE ${SRC_FILES})
    # Extract filename without extension from path
    get_filename_component(EXEC_NAME ${SRC_FILE} NAME_WE)
    
    # Create executable
    add_executable(${EXEC_NAME} ${SRC_FILE})
    
    # Link to core library (dependencies are automatically inherited)
    target_link_libraries(${EXEC_NAME} PRIVATE dns_sak_core)
    
    message(STATUS "Added executable target: ${EXEC_NAME}")
endforeach()

# ==========================================================
#       Create executables from test directory
# ==========================================================
file(GLOB TEST_FILES "test/*.c")

foreach(TEST_FILE ${TEST_FILES})
    # Extract filename
    get_filename_component(BASE_NAME ${TEST_FILE} NAME_WE)
    set(EXEC_NAME "test_${BASE_NAME}") # Add "test_" prefix to avoid name collisions

    # Create executable
    add_executable(${EXEC_NAME} ${TEST_FILE})
    
    # Link to core library
    target_link_libraries(${EXEC_NAME} PRIVATE dns_sak_core)

    message(STATUS "Added test executable target: ${EXEC_NAME}")
endforeach()


# ==========================================================
#                  Testing (Optional)
# ==========================================================

# enable_testing()

# # Example: How to add a CTest test for one of the test targets
# # Need to add an add_test call for each target you want to run via CTest
# if(TARGET test_ipfragment)
#     add_test(
#         NAME IP_Fragmentation_Test
#         COMMAND test_ipfragment # CTest will execute this executable
#     )
# endif()