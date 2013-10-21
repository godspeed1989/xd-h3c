xd-h3c
======
xd-h3c是适用于西电北校区的UNIX/Linux网络客户端。    
纯CLI，在系统无法进入GUI（无法使用官方客户端）而又需要网络进行修复时，是一个很好的选择。   
当然，如果你追求高效或是想找一个在OpenWRT运行的校园网客户端，xd-h3c也是个很不错的选择。   

CONTACT
=======
godspeed1989@gmail.com

INSTALL
=======
安装依赖库 libpcap

```
sudo apt-get install libpcap-dev
```

编译

```
make
```

COMMAND
=======
Usage：

```
	sudo ./xdh3c -u [用户名] -p [密码] -n [网卡名称]
```

使用 ./xdh3c -u 按照提示输入。   
使用 ./xdh3c -l [网卡名称] 注销登录。   
使用 Ctrl^C 注销登录并退出程序。   
使用  --help 来查看详细帮助。    

REFERENCE
=========
Ethernet_frame   
http://en.wikipedia.org/wiki/Ethernet_frame   
IEEE_802.1X   
http://en.wikipedia.org/wiki/IEEE_802.1X   
RFC 3748   
http://tools.ietf.org/html/rfc3748   

