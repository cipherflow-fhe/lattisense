find_package(SEAL 4.1.1 EXACT REQUIRED)
set(SEAL_DIR /usr/local/include/SEAL-4.1)

add_subdirectory(acc)
add_subdirectory(test_acc)
