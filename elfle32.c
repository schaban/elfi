/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2023 Sergey Chaban <sergey.chaban@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elfle32.h"

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

int elfle32_valid(void* pELF) {
	int res = 0;
	if (pELF) {
		uint8_t* p = (uint8_t*)pELF;
		if (p[0] == 0x7F && p[1] == 0x45 && p[2] == 0x4C && p[3] == 0x46) {
			if (p[4] == 1) { /* 32-bit? */
				if (p[5] == 1) { /* little-endian */
					res = 1;
				}
			}
		}
	}
	return res;
}

void* elfle32_load(const char* pPath, size_t* pSize) {
	size_t size = 0;
	void* pELF = NULL;
	if (pPath) {
		pELF = bin_load(pPath, &size);
		if (pELF && size > 0x10) {
			if (!elfle32_valid(pELF)) {
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
	if (pSize) {
		*pSize = size;
	}
	return pELF;
}

uint32_t elfle32_entry_point(void* pELF) {
	uint32_t entry = 0;
	if (elfle32_valid(pELF)) {
		memcpy(&entry, (uint8_t*)pELF + 0x18, 4);
	}
	return entry;
}

uint32_t elfle32_prog_header_offs(void* pELF) {
	uint32_t offs = 0;
	if (elfle32_valid(pELF)) {
		memcpy(&offs, (uint8_t*)pELF + 0x1C, 4);
	}
	return offs;
}

uint32_t elfle32_sect_header_offs(void* pELF) {
	uint32_t offs = 0;
	if (elfle32_valid(pELF)) {
		memcpy(&offs, (uint8_t*)pELF + 0x20, 4);
	}
	return offs;
}

uint32_t elfle32_sect_header_entry_size(void* pELF) {
	uint16_t size = 0;
	if (elfle32_valid(pELF)) {
		memcpy(&size, (uint8_t*)pELF + 0x2E, 2);
	}
	return size;
}

uint32_t elfle32_num_sect_header_entries(void* pELF) {
	uint16_t num = 0;
	if (elfle32_valid(pELF)) {
		memcpy(&num, (uint8_t*)pELF + 0x30, 2);
	}
	return num;
}

uint32_t elfle32_sect_names_entry_id(void* pELF) {
	uint16_t id = 0;
	if (elfle32_valid(pELF)) {
		memcpy(&id, (uint8_t*)pELF + 0x32, 2);
	}
	return id;
}

int elfle32_find_section(void* pELF, const char* pSectName) {
	int idx = -1;
	uint32_t nsects = elfle32_num_sect_header_entries(pELF);
	if (pSectName && nsects > 0) {
		uint32_t hoffs = elfle32_sect_header_offs(pELF);
		uint32_t esize = elfle32_sect_header_entry_size(pELF);
		if (hoffs > 0 && esize > 0) {
			uint32_t nid = elfle32_sect_names_entry_id(pELF);
			if (nid < nsects) {
				uint32_t nameStrsOffs = 0;
				memcpy(&nameStrsOffs, (uint8_t*)pELF + hoffs + nid*esize + 0x10, 4);
				if (nameStrsOffs > 0) {
					uint32_t i;
					for (i = 0; i < nsects; ++i) {
						uint32_t nameOffs = 0;
						memcpy(&nameOffs, (uint8_t*)pELF + hoffs + i*esize, 4);
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

void elfle32_section_addrinfo(void* pELF, int isect, uint32_t* pAddr, uint32_t* pOffs, uint32_t* pSize) {
	uint32_t addr = 0;
	uint32_t offs = 0;
	uint32_t size = 0;
	uint32_t nsects = elfle32_num_sect_header_entries(pELF);
	if ((uint32_t)isect < nsects) {
		uint32_t hoffs = elfle32_sect_header_offs(pELF);
		uint32_t esize = elfle32_sect_header_entry_size(pELF);
		uint8_t* pInfoTop = (uint8_t*)pELF + hoffs + isect*esize;
		memcpy(&addr, pInfoTop + 0x0C, 4);
		memcpy(&offs, pInfoTop + 0x10, 4);
		memcpy(&size, pInfoTop + 0x14, 4);
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

static void sym_foreach_sub(void* pELF, elfle32_symfn fn, void* pCtx, int mode, int* pSymCount) {
	int isymtab = elfle32_find_section(pELF, ".symtab");
	int istrtab = elfle32_find_section(pELF, ".strtab");
	int symCnt = 0;
	if (isymtab >= 0 && istrtab >= 0) {
		uint32_t symtabOffs = 0;
		uint32_t symtabSize = 0;
		uint32_t strtabOffs = 0;
		uint32_t strtabSize = 0;
		elfle32_section_addrinfo(pELF, isymtab, NULL, &symtabOffs, &symtabSize);
		elfle32_section_addrinfo(pELF, istrtab, NULL, &strtabOffs, &strtabSize);
		if (symtabOffs > 0 && symtabSize > 0xF && strtabOffs > 0 && strtabSize > 0) {
			uint32_t i;
			uint32_t nsym = symtabSize / 0x10;
			uint8_t* pSym = (uint8_t*)pELF + symtabOffs;
			for (i = 0; i < nsym; ++i) {
				int cont = 1;
				const char* pName;
				uint32_t nameOffs;
				uint32_t symAddr;
				uint32_t symSize;
				uint32_t symAttr;
				memcpy(&nameOffs, pSym, 4);
				memcpy(&symAddr, pSym + 4, 4);
				memcpy(&symSize, pSym + 8, 4);
				memcpy(&symAttr, pSym + 12, 4);
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
				pSym += 0x10;
			}
		}
	}
	if (pSymCount) {
		*pSymCount = symCnt;
	}
}

void elfle32_foreach_sym(void* pELF, elfle32_symfn fn, void* pCtx) {
	sym_foreach_sub(pELF, fn, pCtx, 0, NULL);
}

void elfle32_foreach_global_func(void* pELF, elfle32_symfn fn, void* pCtx) {
	sym_foreach_sub(pELF, fn, pCtx, 1, NULL);
}

int elfle32_num_global_funcs(void* pELF) {
	int cnt = 0;
	sym_foreach_sub(pELF, NULL, NULL, 1, &cnt);
	return cnt;
}
