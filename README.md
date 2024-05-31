
# 使用stm32芯片实现 SHA1withRSA 加密

## 芯片

· 芯片：stm32f103ZE
· 加密库：mbedtls

使用GPT辅助理解各个api含义

### 目录

- mbedtls   是加密算法库
- Project   kile项目入口文件
- User      程序代码主入口

### 注意事项

如果自己要移植到其它项目里需要需要注意栈堆的初始化大小
可以修改 startup_stm32xxx_xx.s 的程序执行文件里面的
Stack_Size      EQU     0x00000F00
Heap_Size       EQU     0x00000F00
