# Introduction

FirmOctopus is a personal one-click firmware information collection script that will continue to be updated.

![83b48fe032f2f2455766c2ada694860](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/83b48fe032f2f2455766c2ada694860.jpg)

Currently, it implements a one-click solution to:

+ Discover startup scripts
+ Detect HTTPD service binary files (this feature still needs some improvement as it may sometimes result in false positives, but it's better than FirmWalker, which relies on filename matching...)
+ Determine HTTPD service types (PHP, Goahead, Lua, Asp, NGINX, Boa...)
+ Identify version numbers (for some HTTPD service types)
+ Discover sensitive files
+ You can easily expand the above keywords for secondary development

The reason for creating this tool is that, personally, I found FirmWalker to be less useful in real-world scenarios. The output is entirely in white, and the information lacks a hierarchical structure. It even relies on filename matching to discover HTTPD service files.

Additionally, it's not very convenient to extend features, as everything is hardcoded in command lines, making it difficult to add more specific elements. In real-world use, relying on `find` and `grep` operations is very repetitive.

In fact, these two methods can be encapsulated, and we only need to focus on keywords that are worth attention and add them.

# Usage

Download `octopus_en.py`.

```
python octopus_en.py [filesystem path]
```
Recommended usage: Personally, I place it in the ~/ directory. After navigating to the file system path, right-click in WSL and run:
```
python ~/octopus_en.py ./
```

This version is now fully translated into English and includes the filename change from `octopus.py` to `octopus_en.py`.
                                     
