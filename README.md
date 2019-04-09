## 拦截未备案的域名

### 编译

需要uthash
```
cd /usr/src
git clone https://github.com/troydhanson/uthash.git
```

### 有关文件

白名单域名或IP，放在以下2个文件中即可。

whitelist.txt

dnslist.txt

### 网络结构

假定服务器 eth1 用来抓包，eth0用来通信

注意eth0发出的数据包，会伪造源地址，因此网络设备要允许（注意urpf）


### 执行例子

```
while true; 
do 

#update your dnslist.txt whitelist.txt

./webcontrol -t -i eth1 -f "(dst net 202.38.64.0/19 or dst net 210.45.64.0/20) and tcp and (dst port 80 or dst port 8080 or dst port 443)" | tee `date +%Y-%m-%d-%H-%M`.log

done
```

