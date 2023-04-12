# cdnChecker

一款识别域名是否使用cdn的工具



## 背景

红队打点时经常会有收集子域名然后转成ip进而扩展ip段进行脆弱点寻找的需求，如果域名使用cdn，会导致收集错误的ip段，因此我们需要排除cdn来收集更准确的ip地址。

现有的一些识别cdn的工具存在如下问题：

- *仅根据cname或ip范围判断cdn，cname与ip范围不全导致遗漏*

- *输出字段较多，不方便直接与其他工具结合*



同时受到https://github.com/projectdiscovery/ 很多工具的启发，本工具的设计目标就是仅做cdn识别这一项功能，同时可以仅输出未使用cdn的ip，便于直接与其他工具联动，比如 https://github.com/projectdiscovery/mapcidr ，方便直接生成目标ip段



## 安装

```
git clone https://github.com/alwaystest18/cdnChecker.git
cd cdnChecker/
go install
go build cdnChecker.go
```



## 使用

速度测试：实际测试13361个域名耗时82s

参数说明

```
Usage of ./cdnChecker:
  -cf string         //cdn cname文件，默认为同目录cdn_cname
        cdn cname file (default "cdn_cname")
  -df string         //域名列表文件，注意为host部分，不要带http://
        domain list file
  -o string         //未使用cdn域名输出文件，如果不指定生成在同目录no_cdn_domains+时间.txt
        output domains that are not using cdn to file (default "no_cdn_domains202304040755.txt")
  -oc string     //使用cdn域名输出文件，如果不指定生成在同目录use_cdn_domains+时间.txt
        output domains that are using cdn to file (default "use_cdn_domains202304040755.txt")
  -od string     //域名:ip的格式，便于根据ip反查域名，如果不指定生成在同目录domain_info+时间.txt
        output domain info(domain:ip) to file (default "domain_info202304122222.txt")
  -oi string    //未使用cdn的ip输出文件，如果不指定生成在同目录no_cdn_ips+时间.txt
        output ips that are not using cdn to file (default "no_cdn_ips202304040755.txt")
  -r string       //dns服务器列表文件
        dns resolvers file
```

单独使用

```
$ cat domains.txt 
www.baidu.com        //使用cdn
www.qq.com         //使用cdn
www.alibabagroup.com    //使用cdn
aurora.tencent.com     //未使用cdn
$ ./cdnChecker -df domains.txt -cf cdn_cname -r resolvers.txt 
43.137.23.148
```

结合[mapcidr](https://github.com/projectdiscovery/mapcidr ) 可直接生成ip段

```
$./cdnChecker -df domains.txt -cf cdn_cname -r resolvers.txt | mapcidr -aggregate-approx -silent
43.137.23.148/32
```

**强烈推荐dns服务器列表使用自带的resolvers.txt（均为国内dns服务器且验证可用），如果服务器数量过少，大量的dns查询会导致timeout，影响查询准确度**



## 识别cdn思路

主要通过多个dns服务器节点获取域名解析ip，如果存在4个以上不同的ip段，则判断使用cdn，反之未使用cdn。但是直接通过dns服务器查询会增加网络开销影响速度，因此先通过以下方法完成初步筛选：

1.通过https://github.com/projectdiscovery/dnsx 自带的checkCdn方法（通过ip范围判断，主要为国外cdn厂商，对国内cdn识别效果不理想）

2.存在A记录但不存在cname的域名直接判断未使用cdn

3.存在cname的与cdn name列表对比，如果包含cdn cname列表则判断使用cdn



## 常见问题

结果中使用cdn域名列表与未使用cdn域名列表数量相加与实际测试域名数量不符？

答：对于无法获取解析ip的域名，程序会默认为域名无效过滤掉



## 感谢

https://github.com/xiaoyiios/chinacdndomianlist
