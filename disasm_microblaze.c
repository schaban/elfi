#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "elfi32.h"
#include "disasm_microblaze.h"

typedef struct _SymFnCtx {
	MBDisasm* pDis;
	int idx;
} SymFnCtx;

static int funcs_symfn(int isym, const char* pName, uint32_t addr, uint32_t size, uint32_t attr, void* pCtxMem) {
	SymFnCtx* pCtx = (SymFnCtx*)pCtxMem;
	if (pCtx) {
		MBDisasm* pDis = pCtx->pDis;
		if (pDis) {
			int idx = pCtx->idx;
			pDis->pFuncs[idx].pName = pName;
			pDis->pFuncs[idx].addr = addr;
			pDis->pFuncs[idx].size = size;
			++pCtx->idx;
		}
	}
}

int dismb_init(MBDisasm* pDis, const char* pElfPath) {
	int res = 0;
	if (pDis && pElfPath) {
		memset(pDis, 0, sizeof(MBDisasm));
		pDis->pELF = elfi32_load(pElfPath, &pDis->elfSize);
		if (pDis->pELF) {
			void* pELF = pDis->pELF;
			pDis->itext = elfi32_find_section(pELF, ".text");
			elfi32_section_addrinfo(pELF, pDis->itext, &pDis->textAddr, &pDis->textOffs, &pDis->textSize);
			pDis->numFuncs = elfi32_num_global_funcs(pELF);
			printf("Loaded ELF \"%s\": %d global funcs.\n", pElfPath, pDis->numFuncs);
			printf(".text: addr = 0x%X, offs = 0x%X, size = 0x%X\n", pDis->textAddr, pDis->textOffs, pDis->textSize);
			pDis->pFuncs = (MBFunc*)malloc(sizeof(MBFunc) * pDis->numFuncs);
			if (pDis->pFuncs) {
				SymFnCtx ctx;
				ctx.pDis = pDis;
				ctx.idx = 0;
				elfi32_foreach_global_func(pDis->pELF, funcs_symfn, &ctx);
				res = 1;
			}
		}
	}
	return res;
}

int dismb_find_func(MBDisasm* pDis, const char* pName) {
	int idx = -1;
	if (pName && pDis && pDis->pFuncs) {
		int i;
		for (i = 0; i < pDis->numFuncs; ++i) {
			if (strcmp(pName, pDis->pFuncs[i].pName) == 0) {
				idx = i;
				break;
			}
		}
	}
	return idx;
}

static void instr(uint32_t addr, uint32_t code) {
	const char* pOpName = "";
	int opr3 = 1;
	uint32_t op = (code >> 26) & 0x3F;
	int32_t rD = (code >> 21) & 0x1F;
	int32_t rA = (code >> 16) & 0x1F;
	int32_t rB = (code >> 11) & 0x1F;
	int32_t imm = code & 0xFFFF;
	imm <<= 16;
	imm >>= 16;
	if ((op & ~6) == 0) {
		if ((op & 6) == 6) {
			pOpName = "addkc";
		} else if ((op & 6) == 2) {
			pOpName = "addc";
		} else if ((op & 6) == 4) {
			pOpName = "addk";
		} else {
			pOpName = "add";
		}
	} else if ((op & ~6) == 8) {
		if ((op & 6) == 6) {
			pOpName = "addikc";
		} else if ((op & 6) == 2) {
			pOpName = "addic";
		} else if ((op & 6) == 4) {
			pOpName = "addik";
		} else {
			pOpName = "addi";
		}
		rB = -1;
	} else if ((op & ~6) == 1) {
		if ((op & 6) == 6) {
			pOpName = "rsubkc";
		} else if ((op & 6) == 2) {
			pOpName = "rsubc";
		} else if ((op & 6) == 4) {
			pOpName = "rsubk";
		} else {
			pOpName = "rsub";
		}
	} else if ((op & ~6) == 9) {
		if ((op & 6) == 6) {
			pOpName = "rsubikc";
		} else if ((op & 6) == 2) {
			pOpName = "rsubic";
		} else if ((op & 6) == 4) {
			pOpName = "rsubik";
		} else {
			pOpName = "rsubi";
		}
		rB = -1;
	} else if (op == 0x21) {
		pOpName = "and";
	} else if (op == 0x29) {
		pOpName = "andi";
		rB = -1;
	} else if (op == 0x23) {
		if ((imm >> 10) & 1) {
			pOpName = "pcmpne";
		} else {
			pOpName = "andn";
		}
	} else if (op == 0x2B) {
		pOpName = "andni";
		rB = -1;
	} else if (op == 0x27) {
		if (rD == 0) {
			pOpName = "beq";
		} else if (rD == 0x10) {
			pOpName = "beqd";
		} else if (rD == 5) {
			pOpName = "bge";
		} else if (rD == 0x15) {
			pOpName = "bged";
		} else if (rD == 4) {
			pOpName = "bgt";
		} else if (rD == 0x14) {
			pOpName = "bgtd";
		} else if (rD == 3) {
			pOpName = "ble";
		} else if (rD == 0x13) {
			pOpName = "bled";
		} else if (rD == 2) {
			pOpName = "blt";
		} else if (rD == 0x12) {
			pOpName = "bltd";
		} else if (rD == 1) {
			pOpName = "bne";
		} else if (rD == 0x11) {
			pOpName = "bned";
		}
		rD = -1;
	} else if (op == 0x2F) {
		if (rD == 0) {
			pOpName = "beqi";
		} else if (rD == 0x10) {
			pOpName = "beqid";
		} else if (rD == 5) {
			pOpName = "bgei";
		} else if (rD == 0x15) {
			pOpName = "bgedi";
		} else if (rD == 4) {
			pOpName = "bgti";
		} else if (rD == 0x14) {
			pOpName = "bgtid";
		} else if (rD == 3) {
			pOpName = "blei";
		} else if (rD == 0x13) {
			pOpName = "bleid";
		} else if (rD == 2) {
			pOpName = "blti";
		} else if (rD == 0x12) {
			pOpName = "bltid";
		} else if (rD == 1) {
			pOpName = "bnei";
		} else if (rD == 0x11) {
			pOpName = "bneid";
		}
		rB = -1;
		rD = -1;
	} else if (op == 0x26) {
		if (rA == 0xC) {
			pOpName = "brk";
		} else {
			if (rA & 0x10) {
				int al = (rA >> 2) & 3;
				if (al == 0) {
					pOpName = "brd";
				} else if (al == 1) {
					pOpName = "brld";
				} else if (al == 2) {
					pOpName = "brad";
				} else {
					pOpName = "brald";
				}
			} else {
				if (rA & 8) {
					pOpName = "bra";
				} else {
					pOpName = "br";
				}
				rD = -1;
			}
		}
		rA = -1;
	} else if (op == 0x2E) {
		if (rA == 0xC) {
			pOpName = "brki";
		} else if (rA == 2) {
			pOpName = "mbar";
			imm = rD;
			rD = -1;
			rA = -1;
			rB = -1;
		} else {
			if (rA & 0x10) {
				int al = (rA >> 2) & 3;
				if (al == 0) {
					pOpName = "brid";
					rD = -1;
				} else if (al == 1) {
					pOpName = "brlid";
				} else if (al == 2) {
					pOpName = "braid";
					rD = -1;
				} else {
					pOpName = "bralid";
				}
			} else {
				if (rA & 8) {
					pOpName = "brai";
				} else {
					pOpName = "bri";
				}
				rD = -1;
			}
		}
		rA = -1;
		rB = -1;
	} else if (op == 0x11) {
		int st = (imm >> 9) & 3;
		if (st == 0) {
			pOpName = "bsrl";
		} else if (st == 1) {
			pOpName = "bsra";
		} else if (st == 2) {
			pOpName = "bsll";
		}
	} else if (op == 0x19) {
		int st = (imm >> 9) & 3;
		if (st == 0) {
			pOpName = "bsrli";
		} else if (st == 1) {
			pOpName = "bsrai";
		} else if (st == 2) {
			pOpName = "bslli";
		}
		imm &= 0x1F;
		rB = -1;
	} else if (op == 0x24) {
		if (rB == 0 ) {
			if (imm == 0xE0) {
				pOpName = "clz";
			} else if (imm == 0x61) {
				pOpName = "sext16";
			} else if (imm == 0x60) {
				pOpName = "sext8";
			} else if (imm == 1) {
				pOpName = "sra";
			} else if (imm == 0x21) {
				pOpName = "src";
			} else if (imm == 0x41) {
				pOpName = "srl";
			} else if (imm == 0x1E0) {
				pOpName = "swapb";
			} else if (imm == 0x1E2) {
				pOpName = "swaph";
			}
			opr3 = 0;
		} else {
			pOpName = "-- wdc/wic --";
		}
	} else if (op == 0x5) {
		imm &= 0x3FF;
		if (imm == 1) {
			pOpName = "cmp";
		} else if (imm == 3) {
			pOpName = "cmpu";
		}
	} else if (op == 0x16) {
		int subop = (imm >> 7) & 0xF;
		if (subop == 0) {
			pOpName = "fadd";
		} else if (subop == 1) {
			pOpName = "frsub";
		} else if (subop == 2) {
			pOpName = "fmul";
		} else if (subop == 3) {
			pOpName = "fdiv";
		} else if (subop == 4) {
			int cmpo = (imm >> 4) & 0xF;
			if (cmpo == 0) {
				pOpName = "fcmp.un";
			} else if (cmpo == 1) {
				pOpName = "fcmp.lt";
			} else if (cmpo == 2) {
				pOpName = "fcmp.eq";
			} else if (cmpo == 3) {
				pOpName = "fcmp.le";
			} else if (cmpo == 4) {
				pOpName = "fcmp.gt";
			} else if (cmpo == 5) {
				pOpName = "fcmp.ne";
			} else if (cmpo == 6) {
				pOpName = "fcmp.ge";
			}
		} else if (subop == 5) {
			pOpName = "flt";
			opr3 = 0;
		} else if (subop == 6) {
			pOpName = "fint";
			opr3 = 0;
		} else if (subop == 7) {
			pOpName = "fsqrt";
			opr3 = 0;
		}
	} else if (op == 0x1B) {
		if ((imm >> 15) & 1) {
			pOpName = "-- put --";
		} else {
			pOpName = "-- get --";
		}
	} else if (op == 0x13) {
		if ((imm >> 10) & 1) {
			pOpName = "-- putd --";
		} else {
			pOpName = "-- getd --";
		}
	} else if (op == 0x12) {
		pOpName = "idiv";
	} else if (op == 0x2C) {
		pOpName = "imm";
		imm &= 0xFFFF;
		rD = -1;
		rA = -1;
		rB = -1;
	} else if (op == 0x30) {
		if (imm & (1 << 7)) {
			pOpName = "lbuea";
		} else {
			if (imm & (1 << 9)) {
				pOpName = "lbur";
			} else {
				pOpName = "lbu";
			}
		}
	} else if (op == 0x38) {
		pOpName = "lbui";
		rB = -1;
	} else if (op == 0x31) {
		if (imm & (1 << 7)) {
			pOpName = "lhuea";
		} else {
			if (imm & (1 << 9)) {
				pOpName = "lhur";
			} else {
				pOpName = "lhu";
			}
		}
	} else if (op == 0x39) {
		pOpName = "lhui";
		rB = -1;
	} else if (op == 0x32) {
		if (imm & (1 << 10)) {
			pOpName = "lwx";
		} else {
			if (imm & (1 << 7)) {
				pOpName = "lwea";
			} else {
				if (imm & (1 << 9)) {
					pOpName = "lwr";
				} else {
					pOpName = "lw";
				}
			}
		}
	} else if (op == 0x3A) {
		pOpName = "lwi";
		rB = -1;
	} else if (op == 0x25) {
		pOpName = "-- mfs/msrclr/msrset/mts -- ";
	} else if (op == 0x10) {
		imm &= 0x7FF;
		if (imm == 0) {
			pOpName = "mul";
		} else if (imm == 1) {
			pOpName = "mulh";
		} else if (imm == 2) {
			pOpName = "mulhsu";
		} else if (imm == 3) {
			pOpName = "mulhu";
		}
	} else if (op == 0x18) {
		pOpName = "muli";
		rB = -1;
	} else if (op == 0x20) {
		if ((imm >> 10) & 1) {
			pOpName = "pcmpbf";
		} else {
			pOpName = "or";
		}
	} else if (op == 0x28) {
		pOpName = "ori";
		rB = -1;
	} else if (op == 0x22) {
		if ((imm >> 10) & 1) {
			pOpName = "pcmpeq";
		} else {
			pOpName = "xor";
		}
	} else if (op == 0x2D) {
		if (rD == 0x12) {
			pOpName = "rtbd";
		} else if (rD == 0x11) {
			pOpName = "rtid";
		} else if (rD == 0x14) {
			pOpName = "rted";
		} else if (rD == 0x10) {
			pOpName = "rtsd";
		}
		rD = -1;
		rB = -1;
	} else if (op == 0x34) {
		if (imm & (1 << 7)) {
			pOpName = "sbea";
		} else {
			if (imm & (1 << 9)) {
				pOpName = "sbr";
			} else {
				pOpName = "sb";
			}
		}
	} else if (op == 0x3C) {
		pOpName = "sbi";
		rB = -1;
	} else if (op == 0x35) {
		if (imm & (1 << 7)) {
			pOpName = "shea";
		} else {
			if (imm & (1 << 9)) {
				pOpName = "shr";
			} else {
				pOpName = "sh";
			}
		}
	} else if (op == 0x3D) {
		pOpName = "shi";
		rB = -1;
	} else if (op == 0x36) {
		if (imm & (1 << 7)) {
			pOpName = "swea";
		} else if (imm & (1 << 10)) {
			pOpName = "swx";
		} else {
			if (imm & (1 << 9)) {
				pOpName = "swr";
			} else {
				pOpName = "sw";
			}
		}
	} else if (op == 0x3E) {
		pOpName = "swi";
		rB = -1;
	} else if (op == 0x2A) {
		pOpName = "xori";
		rB = -1;
	}
	printf("%08X: %08X   %s\t", addr, code, pOpName);
	if (rD >= 0) {
		printf("r%d, ", rD);
	}
	if (rA >= 0) {
		printf("r%d%s", rA, opr3 ? ", " : "");
	}
	if (opr3) {
		if (rB >= 0) {
			printf("r%d", rB);
		} else {
			printf("%d", imm);
		}
	}
	printf("\n");
}

void dismb_func(MBDisasm* pDis, int ifunc) {
	uint32_t i;
	uint32_t addr;
	uint32_t offs;
	uint32_t ninstrs;
	if (!pDis) {
		return;
	}
	if ((uint32_t)ifunc >= (uint32_t)pDis->numFuncs) {
		fprintf(stderr, "invalid func id: %d\n", ifunc);
		return;
	}
	addr = pDis->pFuncs[ifunc].addr;
	offs = pDis->textOffs + (addr - pDis->textAddr);
	ninstrs = pDis->pFuncs[ifunc].size / 4;
	printf("function \"%s\": addr=0x%X, offs=0x%X, #instrs=%d\n", pDis->pFuncs[ifunc].pName, addr, offs, ninstrs);
	for (i = 0; i < ninstrs; ++i) {
		uint32_t code = elfi32_read_u32(pDis->pELF, offs);
		instr(addr, code);
		offs += 4;
		addr += 4;
	}
}
