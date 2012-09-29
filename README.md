xd-h3c
======
xd-h3c是适用于西电北校区的 h3c UNIX/Linux 下上网客户端。    
当然，iNode也可以用，但是，难道不起动X就不可以上网吗？    
I use it every day now, need your test!!!    

CONTACT
=======
godspeed1989@gmail.com

DEPENDENCY
=========
安装依赖库 libpcap 和 libgcrypt：   
$ sudo apt-get install libpcap-dev    
$ sudo apt-get install libgcrypt-dev    

COMMAND
=======
规则：
	sudo ./xdh3c -u [用户名] -p [密码] -d [网卡名称]    
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

