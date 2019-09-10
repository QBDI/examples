cmake_minimum_required (VERSION 3.5)

set(QBDI_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/QBDI/include")
set(QBDI_LIB          "${CMAKE_CURRENT_SOURCE_DIR}/deps/QBDI/libQBDI.so")

set(LIEF_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/deps/LIEF/include")
set(LIEF_LIB          "${CMAKE_CURRENT_SOURCE_DIR}/deps/LIEF/libLIEF.a")

add_executable(libshellx_qbdi libshellx_qbdi.cpp)

set_property(TARGET libshellx_qbdi PROPERTY CXX_STANDARD           11)
set_property(TARGET libshellx_qbdi PROPERTY CXX_STANDARD_REQUIRED  ON)

target_link_libraries(libshellx_qbdi z ${LIEF_LIB} ${QBDI_LIB})

target_include_directories(libshellx_qbdi PUBLIC ${QBDI_INCLUDE_DIRS})
target_include_directories(libshellx_qbdi PUBLIC ${LIEF_INCLUDE_DIRS})

set_property(
  TARGET libshellx_qbdi APPEND_STRING
  PROPERTY LINK_FLAGS "-Wl,-rpath=/data/local/tmp"
)

add_custom_target(push
  COMMAND
    # Push the Binary
    adb push $<TARGET_FILE:libshellx_qbdi> /data/local/tmp
  COMMAND
    # Push libQBDI.so
    adb push ${QBDI_LIB} /data/local/tmp
  COMMAND
    # Push libshellx without constructors
    adb push ${CMAKE_CURRENT_SOURCE_DIR}/libshellx/libshellx-3.0.0.0_WITHOUT_CTOR.so /data/local/tmp
  DEPENDS libshellx_qbdi)



