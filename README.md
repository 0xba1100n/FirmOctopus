# 简介
firmwalker其实个人感受是并不好用。输出全白，信息没有主次之分，甚至还是依靠文件名匹配来发现httpd服务文件

所以就自己写了一个分类更合理，更自动化地发现一些东西，节省一些文件系统信息侦查时间


# 用法

下载octopus.py

python octopus.py [文件系统路径]


# 效果

## 功能1：匹配网页文件php,asp,htm,html,py,jsp,cgi,lua等等
![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723123504.png)

## 功能2：一些常见的敏感文件（现在主要包含passwd、shadow这些）

![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723123613.png)

## 功能3：对非二进制的、非网页端的文件，即很多都是配置文件，进行关键词匹配

![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723123652.png)

## 功能4：侦查一下启动脚本，这个目前还是基于init.d目录看看

![](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723124009.png)

## 功能5：使用函数名等方法，寻找HTTPD服务文件，而不是仅仅只匹配文件名

![](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723124105.png)

## 功能6：通过find、grep的方式，判别当前固件存在的服务类型
![](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723124313.png)
![](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723124240.png)



## 功能7：直接发现版本号（待完善）
目前支持goahead
![](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723124557.png)

# 补充
