# 简介
FirmOctoupus(固件章鱼)是一个目前自用的一键固件信息收集脚本，会继续持续更新

![83b48fe032f2f2455766c2ada694860](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/83b48fe032f2f2455766c2ada694860.jpg)

目前实现了只要一键就可以：

+ 启动文件夹发现

+ HTTPD服务二进制文件发现（这个还需要稍微完善功能有时候误报，但毕竟比firmwalker基于文件名匹配更好吧。。。）

+ HTTPD服务类别判定（PHP、Goahead、Lua、Asp、NGINX、Boa...）

+ 版本号识别（部分httpd服务类别）

+ 敏感文件发现

+ 随时可以扩充以上的关键字来进行二开

造这个轮子的初衷是firmwalker其实个人感受是实战多了感觉并不好用。输出全白，信息没有主次之分，甚至还是依靠文件名匹配来发现httpd服务文件

而且也不算很方便扩充一些特征，因为都是写死的shell，而在实战中依赖find,grep的操作又非常同质化，

其实可以封装起来这两种方法，然后我们就只需要关心有关键字值得关注然后加进去

# 用法

下载octopus.py

python octopus.py [文件系统路径]

推荐用法：我个人其实是放到~/下，每次转到文件系统路径后右键wsl然后

python ~/octopus.py ./

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



## 功能7：待完善的，针对每种固件的进一步信息发现
目前支持发现goahead版本号（不一定有好像）
![](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723124557.png)

nginx的路由文件
![](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20250723125907.png)
# 补充
