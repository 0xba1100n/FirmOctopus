
# 简介
firmwalker感觉太眼花了一片全白，容易导致疏漏重要信息，而且让人不想看，所以就自己写了一个分类更合理，
并且实现一定信息降噪的功能（排除掉结果里面对一些文件的显示，保护眼睛健康）

除了如firmwalker检测httpd文件名，还会对常见httpd函数进行检测，以提高httpd发现率，只要动态链接库的符号表还在，这种方法就可靠，不过目前还没有完善到很好的程度，日后将持续收集各种类型httpd的常见函数


# 效果
![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250715170251.png)

![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250715170232.png)


![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250715165948.png)

想增添关键词的检测非常简单，在这加就好
![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250715170206.png)


![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250715170106.png)

![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250715170122.png)

# TODO
引入GPT感觉可以实现信息上的极大降噪，但感觉暂时没有必要了，可以直接复制粘贴丢框框

(目前的版本有点水，实际上很多厉害的师傅自己私藏的实现很不错，如果能issue拷打一起维护，i would appreciate
