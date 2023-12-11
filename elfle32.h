/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2023 Sergey Chaban <sergey.chaban@gmail.com> */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*elfle32_symfn)(int isym, const char* pName, uint32_t addr, uint32_t size, uint32_t attr, void* pCtx);

int elfle32_valid(void* pELF);
void* elfle32_load(const char* pPath, size_t* pSize);
uint32_t elfle32_entry_point(void* pELF);
uint32_t elfle32_prog_header_offs(void* pELF);
uint32_t elfle32_sect_header_offs(void* pELF);
uint32_t elfle32_sect_header_entry_size(void* pELF);
uint32_t elfle32_num_sect_header_entries(void* pELF);
uint32_t elfle32_sect_names_entry_id(void* pELF);
int elfle32_find_section(void* pELF, const char* pSectName);
void elfle32_section_addrinfo(void* pELF, int isect, uint32_t* pAddr, uint32_t* pOffs, uint32_t* pSize);
void elfle32_foreach_sym(void* pELF, elfle32_symfn fn, void* pCtx);
void elfle32_foreach_global_func(void* pELF, elfle32_symfn fn, void* pCtx);
int elfle32_num_global_funcs(void* pELF);

#ifdef __cplusplus
}
#endif


