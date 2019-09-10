/*
 * This file is part of QBDI.
 *
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef _VERSION_H_
#define _VERSION_H_

#include <stdint.h>
#include "Platform.h"

#ifdef __cplusplus
namespace QBDI {
extern "C" {
#endif

#define QBDI_VERSION 0x070
#define QBDI_VERSION_STRING "0.7.0-devel"

#define QBDI_VERSION_MAJOR 0
#define QBDI_VERSION_MINOR 7
#define QBDI_VERSION_PATCH 0
#define QBDI_VERSION_DEV 1

/*! Return QBDI version.
 *
 * @param[in] version    QBDI version encoded as an unsigned integer (0xMmp).
 * @return  QBDI version as a string (major.minor.patch).
 */
QBDI_EXPORT const char* qbdi_getVersion(uint32_t* version);

#ifdef __cplusplus
/*
 * C API C++ bindings
 */
inline const char* getVersion(uint32_t* version) {
    return qbdi_getVersion(version);
}

} // "C"
} // QBDI::
#endif

#endif // _VERSION_H_