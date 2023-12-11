/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2023 Sergey Chaban <sergey.chaban@gmail.com> */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*elfi32_symfn)(int isym, const char* pName, uint32_t addr, uint32_t size, uint32_t attr, void* pCtx);

int elfi32_is_le_sys();
int elfi32_valid(void* pELF);
void elfi32_set_swap(void* pELF);
void* elfi32_load(const char* pPath, size_t* pSize);
uint8_t elfi32_read_u8(void* pELF, uint32_t offs);
uint16_t elfi32_read_u16(void* pELF, uint32_t offs);
uint32_t elfi32_read_u32(void* pELF, uint32_t offs);
uint32_t elfi32_entry_point(void* pELF);
uint32_t elfi32_prog_header_offs(void* pELF);
uint32_t elfi32_sect_header_offs(void* pELF);
uint32_t elfi32_sect_header_entry_size(void* pELF);
uint32_t elfi32_num_sect_header_entries(void* pELF);
uint32_t elfi32_sect_names_entry_id(void* pELF);
int elfi32_find_section(void* pELF, const char* pSectName);
void elfi32_section_addrinfo(void* pELF, int isect, uint32_t* pAddr, uint32_t* pOffs, uint32_t* pSize);
void elfi32_foreach_sym(void* pELF, elfi32_symfn fn, void* pCtx);
void elfi32_foreach_global_func(void* pELF, elfi32_symfn fn, void* pCtx);
int elfi32_num_global_funcs(void* pELF);

#ifdef __cplusplus
}
#endif

