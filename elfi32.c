/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2023 Sergey Chaban <sergey.chaban@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elfi32.h"

int elfi32_is_le_sys() {
	static const char* pStr = "LE32";
	union {
		uint32_t u;
		uint8_t b[4];
	} bits;
	int i;
	uint32_t cc = 0;
	for (i = 0; i < 4; ++i) {
		bits.b[i] = pStr[i];
		cc |= (uint32_t)bits.b[i] << (i << 3);
	}
	return (cc == bits.u);
}

static size_t file_size(FILE* pFile) {
	size_t size = 0;
	if (pFile) {
		long fpos = ftell(pFile);
		if (fpos >= 0) {
			if (fseek(pFile, 0, SEEK_END) == 0) {
				long flen = ftell(pFile);
				if (flen >= 0) {
					size = (size_t)flen;
				}
			}
			fseek(pFile, fpos, SEEK_SET);
		}
	}
	return size;
}

static size_t file_read(FILE* pFile, void* pDst, size_t size) {
	size_t nread = 0;
	if (pFile && pDst && size > 0) {
		nread = fread(pDst, 1, size, pFile);
	}
	return nread;
}

static void* bin_load(const char* pPath, size_t* pSize) {
	void* pData = NULL;
	size_t size = 0;
	if (pPath) {
		FILE* pFile = fopen(pPath, "rb");
		if (pFile) {
			size = file_size(pFile);
			if (size > 0) {
				pData = malloc(size);
				if (pData) {
					fseek(pFile, 0, SEEK_SET);
					size = file_read(pFile, pData, size);
				}
			}
			fclose(pFile);
		}
	}
	if (pSize) {
		*pSize = size;
	}
	return pData;
}

int elfi32_valid(void* pELF) {
	int res = 0;
	if (pELF) {
		uint8_t* p = (uint8_t*)pELF;
		if (p[0] == 0x7F && p[1] == 0x45 && p[2] == 0x4C && p[3] == 0x46) {
			if (p[4] == 1) { /* 32-bit? */
				res = 1;
			}
		}
	}
	return res;
}

void elfi32_set_swap(void* pELF) {
	if (elfi32_valid(pELF)) {
		uint8_t* p = (uint8_t*)pELF;
		if (p[5] == 1) {
			/* little-endian */
			if (!elfi32_is_le_sys()) {
				p[5] |= 0x80;
			}
		} else if (p[5] == 2) {
			/* big-endian */
			if (elfi32_is_le_sys()) {
				p[5] |= 0x80;
			}
		}
	}
}

void* elfi32_load(const char* pPath, size_t* pSize) {
	size_t size = 0;
	void* pELF = NULL;
	if (pPath) {
		pELF = bin_load(pPath, &size);
		if (pELF && size > 0x10) {
			if (!elfi32_valid(pELF)) {
				free(pELF);
				pELF = NULL;
				size = 0;
			}
		} else {
			free(pELF);
			pELF = NULL;
			size = 0;
		}
	}
	elfi32_set_swap(pELF);
	if (pSize) {
		*pSize = size;
	}
	return pELF;
}

uint8_t elfi32_read_u8(void* pELF, uint32_t offs) {
	uint8_t val = 0;
	if (pELF) {
		val = ((uint8_t*)pELF)[offs];
	}
	return val;
}

uint16_t elfi32_read_u16(void* pELF, uint32_t offs) {
	uint16_t val = 0;
	uint8_t* p = (uint8_t*)pELF;
	uint8_t* pDst = (uint8_t*)&val;
	if (p[5] & 0x80) {
		uint8_t* pSrc = p + offs + 1;
		*pDst++ = *pSrc--;
		*pDst = *pSrc;
	} else {
		uint8_t* pSrc = p + offs;
		*pDst++ = *pSrc++;
		*pDst = *pSrc;
	}
	return val;
}

uint32_t elfi32_read_u32(void* pELF, uint32_t offs) {
	int i;
	uint32_t val = 0;
	uint8_t* p = (uint8_t*)pELF;
	uint8_t* pDst = (uint8_t*)&val;
	if (p[5] & 0x80) {
		uint8_t* pSrc = p + offs + 3;
		for (i = 0; i < 4; ++i) {
			*pDst++ = *pSrc--;
		}
	} else {
		uint8_t* pSrc = p + offs;
		for (i = 0; i < 4; ++i) {
			*pDst++ = *pSrc++;
		}
	}
	return val;
}

uint32_t elfi32_entry_point(void* pELF) {
	uint32_t addr = 0;
	if (elfi32_valid(pELF)) {
		addr = elfi32_read_u32(pELF, 0x18);
	}
	return addr;
}

uint32_t elfi32_prog_header_offs(void* pELF) {
	uint32_t offs = 0;
	if (elfi32_valid(pELF)) {
		offs = elfi32_read_u32(pELF, 0x1C);
	}
	return offs;
}

uint32_t elfi32_sect_header_offs(void* pELF) {
	uint32_t offs = 0;
	if (elfi32_valid(pELF)) {
		offs = elfi32_read_u32(pELF, 0x20);
	}
	return offs;
}

uint32_t elfi32_sect_header_entry_size(void* pELF) {
	uint16_t size = 0;
	if (elfi32_valid(pELF)) {
		size = elfi32_read_u16(pELF, 0x2E);
	}
	return size;
}

uint32_t elfi32_num_sect_header_entries(void* pELF) {
	uint16_t num = 0;
	if (elfi32_valid(pELF)) {
		num = elfi32_read_u16(pELF, 0x30);
	}
	return num;
}

uint32_t elfi32_sect_names_entry_id(void* pELF) {
	uint16_t id = 0;
	if (elfi32_valid(pELF)) {
		id = elfi32_read_u16(pELF, 0x32);
	}
	return id;
}

int elfi32_find_section(void* pELF, const char* pSectName) {
	int idx = -1;
	uint32_t nsects = elfi32_num_sect_header_entries(pELF);
	if (pSectName && nsects > 0) {
		uint32_t hoffs = elfi32_sect_header_offs(pELF);
		uint32_t esize = elfi32_sect_header_entry_size(pELF);
		if (hoffs > 0 && esize > 0) {
			uint32_t nid = elfi32_sect_names_entry_id(pELF);
			if (nid < nsects) {
				uint32_t nameStrsOffs = elfi32_read_u32(pELF, hoffs + nid*esize + 0x10);
				if (nameStrsOffs > 0) {
					uint32_t i;
					for (i = 0; i < nsects; ++i) {
						uint32_t nameOffs = elfi32_read_u32(pELF, hoffs + i*esize);
						if (strcmp(pSectName, (char*)pELF + nameStrsOffs + nameOffs) == 0) {
							idx = (int)i;
							break;
						}
					}
				}
			}
		}
	}
	return idx;
}

void elfi32_section_addrinfo(void* pELF, int isect, uint32_t* pAddr, uint32_t* pOffs, uint32_t* pSize) {
	uint32_t addr = 0;
	uint32_t offs = 0;
	uint32_t size = 0;
	uint32_t nsects = elfi32_num_sect_header_entries(pELF);
	if ((uint32_t)isect < nsects) {
		uint32_t hoffs = elfi32_sect_header_offs(pELF);
		uint32_t esize = elfi32_sect_header_entry_size(pELF);
		uint32_t infoTop = hoffs + isect*esize;
		addr = elfi32_read_u32(pELF, infoTop + 0x0C);
		offs = elfi32_read_u32(pELF, infoTop + 0x10);
		size = elfi32_read_u32(pELF, infoTop + 0x14);
	}
	if (pAddr) {
		*pAddr = addr;
	}
	if (pOffs) {
		*pOffs = offs;
	}
	if (pSize) {
		*pSize = size;
	}
}

static void sym_foreach_sub(void* pELF, elfi32_symfn fn, void* pCtx, int mode, int* pSymCount) {
	int isymtab = elfi32_find_section(pELF, ".symtab");
	int istrtab = elfi32_find_section(pELF, ".strtab");
	int symCnt = 0;
	if (isymtab >= 0 && istrtab >= 0) {
		uint32_t symtabOffs = 0;
		uint32_t symtabSize = 0;
		uint32_t strtabOffs = 0;
		uint32_t strtabSize = 0;
		elfi32_section_addrinfo(pELF, isymtab, NULL, &symtabOffs, &symtabSize);
		elfi32_section_addrinfo(pELF, istrtab, NULL, &strtabOffs, &strtabSize);
		if (symtabOffs > 0 && symtabSize > 0xF && strtabOffs > 0 && strtabSize > 0) {
			uint32_t i;
			uint32_t nsym = symtabSize / 0x10;
			uint32_t symOffs = symtabOffs;
			for (i = 0; i < nsym; ++i) {
				int cont = 1;
				const char* pName;
				uint32_t nameOffs;
				uint32_t symAddr;
				uint32_t symSize;
				uint32_t symAttr;
				nameOffs = elfi32_read_u32(pELF, symOffs);
				symAddr = elfi32_read_u32(pELF, symOffs + 4);
				symSize = elfi32_read_u32(pELF, symOffs + 8);
				symAttr = elfi32_read_u8(pELF, symOffs + 12);
				symAttr |= elfi32_read_u8(pELF, symOffs + 13) << 8;
				symAttr |= elfi32_read_u16(pELF, symOffs + 14) << 16;
				pName = (const uint8_t*)pELF + strtabOffs + nameOffs;
				if (mode == 1) {
					if ((symAttr & 0xFF) == 0x12) {
						/* BIND(GLOBAL), TYPE(FUNC) */
						if (fn) {
							cont = fn(i, pName, symAddr, symSize, symAttr, pCtx);
						}
						++symCnt;
					}
				} else {
					if (fn) {
						cont = fn(i, pName, symAddr, symSize, symAttr, pCtx);
					}
					++symCnt;
				}
				if (!cont) break;
				symOffs += 0x10;
			}
		}
	}
	if (pSymCount) {
		*pSymCount = symCnt;
	}
}

void elfi32_foreach_sym(void* pELF, elfi32_symfn fn, void* pCtx) {
	sym_foreach_sub(pELF, fn, pCtx, 0, NULL);
}

void elfi32_foreach_global_func(void* pELF, elfi32_symfn fn, void* pCtx) {
	sym_foreach_sub(pELF, fn, pCtx, 1, NULL);
}

int elfi32_num_global_funcs(void* pELF) {
	int cnt = 0;
	sym_foreach_sub(pELF, NULL, NULL, 1, &cnt);
	return cnt;
}
