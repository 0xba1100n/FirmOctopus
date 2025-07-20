
# 简介
firmwalker感觉太眼花了一片全白，容易导致疏漏重要信息，而且让人不想看，所以就自己写了一个分类更合理，
并且实现一定信息降噪的功能（排除掉结果里面对一些文件的显示，保护眼睛健康），目前是自己在用，节省一些文件系统信息侦查时间

如firmwalker检测httpd文件名并不准确，本项目还会对常见httpd函数进行检测，以提高httpd发现率，不过目前还没有完善到很好的程度，日后将持续改进

# 用法

下载octopus.py

python octopus.py [文件系统路径]


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

(目前的版本属于测试版，有些关键词还得靠日后慢慢发掘，实际上很多厉害的师傅自己私藏的实现很不错，如果能issue提出一些建议，我会马上想办法整合进去)
