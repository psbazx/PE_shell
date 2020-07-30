# PE_shell
环境vs2019 win10  
准确来说不是壳子，主要用到的技术是Process Hollowing
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
本来想把重定位写了来完善一下，但是发现操作系统会自动帮我重定位？？？  
感觉和我学的很不一样，但是问题不大，已经是完整版的了，重定位以后用到直接复制了。  
# 预览
![成功截图](https://github.com/psbazx/PE_shell/blob/master/%E6%88%90%E5%8A%9F%E6%88%AA%E5%9B%BE.png)  
first.exe为源程序  
shell.exe为加壳后  
