## 原理简述
命令注入漏洞是指在攻击者通过有此漏洞的应用程序得以在主机上执行任意系统命令的漏洞。
通常情况下，是由于应用程序接收了用户输入（如表单、cookie、HTTP头）没有经过安全的过滤、转义就直接拼接进shell命令执行导致的。
## 危害
直接执行任意系统命令（rm -rf /），入侵服务器

## 如何避免？
1. 首先，能用编程语言函数实现的功能就不要用shell实现。比如：在PHP中使用curl相关函数或file_get_contents()实现获取URL的内容，而不应使用system("curl $url");通过执行shell去获取。
2. 如果一定要使用shell了，那么需要将用户输入用单引号包裹，然后转义输入中的单引号为\'，以保证用户输入只作为命令中的参数而不改变语义。如PHP中：escapeshellarg()函数

> shell中单引号会作为参数处理，而双引号中的符号会解析

## GoodCase
```php
<?php
  //dig一下HTTP请求中的host
  $host = $_SERVER['HTTP_HOST'];
  $res = system('dig '.escapeshellarg($host));
```
## BadCase
```php
<?php
  //实现一个文件下载功能
  $url = $_GET['url'];
  $res = system('wget '.$url);
  //输入URL：http://www.baidu.com;rm -rf —no-preserce-root /
  //Boom!
```

## 我的代码可能有问题，如何排查？
首先当然是排查代码中有没有调用命令的地方啦，比如说PHP中的：
`反引号、 exec、 system、 passthru、 pcntl_exec、 shell_exec、 popen、 proc_open、 expect_popen、 mail、 mb_send_mail`
Java中的：
`Runtime.getRuntime().exec、Call.setOperationName、ProcessBuilder.start、ProcessBuilder.command`
其他语言的就不列举了，处理原则参考`如何避免`
