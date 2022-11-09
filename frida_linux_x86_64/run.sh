#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QBDI_ARCHIVE="$1"
BUILD_DIRECTORY="$2"

usage() {
  echo "Usage: $0 <QBDI-X.X.X-linux-X86_64.tar.gz> <build_dir>"
  exit 1
}

if [[ "$#" -ne 2 ]]; then
  echo "expect 2 arguemnts"
  usage
fi

if [[ ! -f "${QBDI_ARCHIVE}" ]]; then
  echo "Invalid QBDI archive ${QBDI_ARCHIVE}"
  usage
fi

if [[ ! -e "${BUILD_DIRECTORY}" ]]; then
  mkdir -p "${BUILD_DIRECTORY}"
fi

if [[ ! -d "${BUILD_DIRECTORY}" ]]; then
  echo "Invalid build directory ${QBDI_ARCHIVE}"
  usage
fi

# Absolute path
QBDI_ARCHIVE="$(cd "$(dirname "${QBDI_ARCHIVE}")" && pwd)/$(basename "${QBDI_ARCHIVE}")"
BUILD_DIRECTORY="$(cd "${BUILD_DIRECTORY}" && pwd)"

cd "${BUILD_DIRECTORY}"

#1. install frida
python3 -m pip install --user --upgrade 'frida>=16.0.0' frida-tools
FRIDA_TOOLS_INSTALL_PATH="$(python3 -m pip show frida-tools | grep '^Location:' | sed 's/Location: *//')"
FRIDA_CMD="${FRIDA_TOOLS_INSTALL_PATH}/$(python3 -m pip show frida-tools -f | grep '^  .*/frida$' | tr -d '[:space:]')"

if [[ ! -f "${FRIDA_CMD}" ]]; then
  echo "Fail to find frida CLI binary"
fi

#2. extract QBDI_ARCHIVE
EXTRACTED_QBDI_ARCHIVE="${BUILD_DIRECTORY}/archive"
mkdir -p "${EXTRACTED_QBDI_ARCHIVE}"
tar xf "${QBDI_ARCHIVE}" --directory "${EXTRACTED_QBDI_ARCHIVE}"

find_file() {
  BASE_DIR="$1"
  FILEPATTERN="$2"
  DEST_VAR="$3"

  RES="$(find "${BASE_DIR}" -name "${FILEPATTERN}")"
  if [[ "$(echo "${RES}" | wc -l)" -ne 1 ]] || [[ ! -f ${RES} ]] ; then
    echo "Fail to found ${FILEPATTERN} in ${BASE_DIR}"
    exit 1
  fi
  printf -v "${DEST_VAR}" "%s" "${RES}"
}

find_file "${EXTRACTED_QBDI_ARCHIVE}" "libQBDI.so" QBDI_LIB_PATH
find_file "${EXTRACTED_QBDI_ARCHIVE}" "frida-qbdi.js" QBDI_FRIDAQBDIJS_PATH
ln -f -s "${QBDI_LIB_PATH}" "${BUILD_DIRECTORY}"
ln -f -s "${QBDI_FRIDAQBDIJS_PATH}" "${BUILD_DIRECTORY}"

#3. build src
EXEC_BUILD_DIR="${BUILD_DIRECTORY}/build"
mkdir -p "${EXEC_BUILD_DIR}"
cmake "${SCRIPT_DIR}/src" -B"${EXEC_BUILD_DIR}"
cmake --build "${EXEC_BUILD_DIR}"

EXEC_BIN="${EXEC_BUILD_DIR}/demo.bin"

if [[ ! -f "${EXEC_BIN}" ]]; then
  echo "Fail to generate target binary"
fi

#4. compile the script
BUILD_SCRIPT="${BUILD_DIRECTORY}/script.js"
COMPILED_SCRIPT="${BUILD_DIRECTORY}/scriptCompiled.js"

ln -f -s "${SCRIPT_DIR}/script.js" "${BUILD_SCRIPT}"

npm install frida-compile babelify
./node_modules/.bin/frida-compile "${BUILD_SCRIPT}" -o "${COMPILED_SCRIPT}"

#5. execute
"${FRIDA_CMD}" -f "${EXEC_BIN}" -l "${COMPILED_SCRIPT}"

