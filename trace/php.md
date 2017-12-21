# PHP trouble shoot

## php扩展未加载
- 查看ini文件
```
php --ini
Configuration File (php.ini) Path: /home/users/wangweiwei11/work/php
Loaded Configuration File:         (none)
Scan for additional .ini files in: (none)
Additional .ini files parsed:      (none)
```
- 查看ini文件里面是否配置了extension=xxx.so
- php -m看是否加载了扩展
```
$ php -m
[PHP Modules]
bz2
Core
...
```
- 查看日志
如果配置了扩展，但没有加载，查看log/php/php-error.log看是否有报错
  - can not open shared object file: No such file or directory扩展路径配置错误，找不到扩展文件
  - undefined symbol:zend_new_interned_string扩展是在高版本php下编译的，而当前php版本较低，缺少符号

## 请求阶段问题
- http 302跳转到错误页
  - nginx配置了错误重定向，可以修改nginx配置关闭
  - php代码里面设置了header重定向，可以修改php代码关闭
- http 403 forbidden
  - 访问太频繁，命中防攻击策略了，查看nginx.conf, 如果是误杀设置policy_frame off，关闭防攻击策略
- http 404 not found
  - 输入的url有问题
  - nginx的rewrite规则配置错误，可以开启nginx的debug日志查看rewrite后的url
  - hhvm配置了RequestInitDocument，但该文件不存在
- http 499
  - 服务端响应过慢，客户端等待超时了，主动断开连接
- http 502
  - 检查nginx配置fastcgi_pass设置的值，可能是端口或者sock文件，检查相应的端口或者sock文件是否存在。
    - 端口或sock如果不存在。
        - 可能是php或者hhvm没有启动，尝试启动php、hhvm；
        - 可能是php或者hhvm监听的端口或者sock文件路径配置错误，请查看php/hhvm配置的端口或sock文件路径
    - 端口或sock如果存在。
        - 如果php/hhvm的进程号一直在变化，可能是php或者hhvm在处理请求过程中出core，导致不断地重启；
        - 如果进程号没有变化，top查看一下进程的cpu占用，如果cpu占用较高，可能php或者hhvm压力过大；如果cpu占用较低，可能是php或者hhvm hang死，无法接收请求。
- http 500
  - 查看php-error.log或hhvm-error.log，一般有fatal日志

## 服务响应慢

## 进程出core

## hhvm 异常重启

## php异常重启

## 进程hang死
表现：进程是存活的，但是不工作

## 系统问题
### cpu打满
### 内存泄漏
### fd泄漏
### 磁盘满
