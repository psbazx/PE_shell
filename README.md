# PE_shell
环境vs2019 win10  
准确来说不是壳子，主要用到的技术是Process Hollowing  
具体功能如下，但是我准备用来出题可能有所异同  
## encode.c  
主要功能  
1.抹去dos存根，并新增节  
2.吧壳程序加密放入新增节内  
3.加壳程序完成  
## decode.c  
解密最后一个节，以挂起的形式创建进程，获取主线程contect结构体后卸载外壳，在指定处分配地址然后拉伸后写入  
吧context的eip和imagebase做对应修改  
最后恢复进程，成功脱壳  
## 7.30更新  
本来想把重定位写了来完善一下,但是调试发现操作系统也做了次重定位，如果写的话就是二次重定位了//目前没有搞懂为啥会这样，可能win10内核函数有些不一样  
所以直接virtualalloc即可,不需要重定位，当然重定位函数我也放那了以后有需要直接复制，经测试没问题,踩了很多坑比如重定位的时候变量类型不能是unsigned啥的。。。  
shell.exe是加壳样本，单纯打印字符串供逆向分析用，无毒  
## 使用方法  
编译decode.cpp然后encode.cpp中路径改一下，decode_shell.exe还有待加壳程序路径  
运行encode即可  
注:源程序必须有重定位表  
# 预览
![成功截图](https://github.com/psbazx/PE_shell/blob/master/%E6%88%90%E5%8A%9F%E6%88%AA%E5%9B%BE.png)  
first.exe为源程序  
shell.exe为加壳后  
