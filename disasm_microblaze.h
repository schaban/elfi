typedef struct _MBFunc {
	const char* pName;
	uint32_t addr;
	uint32_t size;
} MBFunc;

typedef struct _MBDisasm {
	void* pELF;
	size_t elfSize;
	int itext;
	uint32_t textAddr;
	uint32_t textOffs;
	uint32_t textSize;
	int numFuncs;
	MBFunc* pFuncs;
} MBDisasm;

int dismb_init(MBDisasm* pDis, const char* pElfPath);
int dismb_find_func(MBDisasm* pDis, const char* pName);
void dismb_func(MBDisasm* pDis, int ifunc);

