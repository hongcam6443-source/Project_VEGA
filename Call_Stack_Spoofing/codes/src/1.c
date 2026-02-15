// 替换原本的入库逻辑
        if(pFoundGadget != NULL){
            // 防御性编程：绝对不能越过我们的数组边界
            if (g_GadgetCount < 100) {
                GoldenGadgets[g_GadgetCount].pGadgetAddress = pFoundGadget;
                GoldenGadgets[g_GadgetCount].dwStackSize = size;
                g_GadgetCount++;
                
                // 找到一个打印一个，享受丰收的喜悦
                // printf("[+] Found Gadget: Address 0x%p, Stack Size: %d bytes\n", pFoundGadget, size);
            }
        }