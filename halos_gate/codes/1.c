// [New] 手动解析导出表 (EAT) 查找函数地址
PVOID GetProcAddress_Hash(PVOID DllBase, DWORD FunctionHash) {
    // 1. 读取 DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)DllBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) // 检查 'MZ'
        return NULL;

    // 2. 读取 NT 头 (Base + e_lfanew)
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)DllBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) // 检查 'PE'
        return NULL;

    // 3. 获取导出表 (Export Directory)
    // 导出表在 DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] (索引 0)
    // VirtualAddress 存的是 RVA (相对偏移)，必须加上 DllBase 才是内存地址
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)DllBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    // 4. 获取三个关键数组的地址 (全都是 RVA，需要 + DllBase)
    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)DllBase + pExport->AddressOfFunctions);
    DWORD* pAddressOfNames     = (DWORD*)((BYTE*)DllBase + pExport->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)DllBase + pExport->AddressOfNameOrdinals);

    // 5. 遍历函数名数组
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        // 获取当前函数名字符串 (RVA -> VA)
        char* functionName = (char*)((BYTE*)DllBase + pAddressOfNames[i]);

        // 计算 ASCII 哈希
        DWORD currentHash = djb2_hash_a(functionName);

        // 6. 匹配哈希
        if (currentHash == FunctionHash) {
            // [Bingo!] 哈希匹配成功
            
            // 步骤 A: 通过索引 i，在 "序号表" 中找到函数的 Ordinal
            WORD ordinal = pAddressOfNameOrdinals[i];

            // 步骤 B: 通过 Ordinal，在 "地址表" 中找到函数的 RVA
            DWORD functionRVA = pAddressOfFunctions[ordinal];

            // 步骤 C: 计算函数在内存中的真实地址 (VA)
            PVOID functionAddress = (PVOID)((BYTE*)DllBase + functionRVA);

            return functionAddress;
        }
    }

    return NULL; // 没找到
}
