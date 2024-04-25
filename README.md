# MoeHoo-NapCat
基于QQ特征码 Hook 实现方案

## Road
## Tools
Cmake + MSVC/GCC + CPP

## InlineHook For Windows X64
通过搜索在大概内存范围搜索一段特殊逻辑的汇编代码，无关地址与偏移。

得到进一步缩小范围，再次搜索关键替换点，搜索到验证被替换函数的逻辑是否正确

如果异常则返回再次搜索，直到搜索到或失败。
