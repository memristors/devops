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
- http 504
  - PHP或者hhvm压力过大，响应超时
  - 请求执行时间过长，响应超时
  - php或hhvm夯死

## 服务响应慢
- 查看日志中的耗时
  - 查看nginx access_log中的响应时间，确认是否服务端请求慢
  - 查看hhvm-access.log或者业务notice日志中的响应时间，确认是否业务处理时间慢，还是在nginx排队时间过长
- 查看slow log
  - php-fpm默认都开启，一般在log/php/php-fpm-slow.log
  - hhvm一般没开启，可以修改hhvm/conf/hhvm.hdf开启，随后如果有超时请求会在log/hhvm/hhvm-error.log中打印调用堆栈
- 工具分析
  - xhprof

## 进程出core
- 查看core位置，会显示绝对位置和相对位置，如果是相对位置则core保存在程序的工作目录
```
cat /proc/sys/kernel/core_pattern
/home/coresave/core.%e.%p.%t
```

>如果没有core文件生成，可能有以下原因.

>系统层面：ulimit -a查看，如果显示core file size (blocks, -c) 0则说明系统限制了不写core文件，这时可以执行ulimit -c unlimited来解除限制，然后重启服务生效

> 进程自己运行时也会修改自己的limits，如hhvm如果配置了ResourceLimit.CoreFileSize=0，也会导致没有core文件，这时只须去掉这项配置，或者将它改成一个比较大的值（如5000000000），就可以打core文件打出来了

>可以通过 cat /proc/$pid/limits的方法查看某个进程的运行时limit
```
cat  /proc/32373/limits
Limit                     Soft Limit           Hard Limit           Units
Max cpu time              unlimited            unlimited            seconds
Max file size             unlimited            unlimited            bytes
Max data size             unlimited            unlimited            bytes
Max stack size            10485760             unlimited            bytes
Max core file size        0                    0                    bytes
Max resident set          3894149120           3894149120           bytes
Max processes             30720                30720                processes
Max open files            10240                10240                files
Max locked memory         65536                65536                bytes
Max address space         4194304000000        4194304000000        bytes
Max file locks            unlimited            unlimited            locks
Max pending signals       256871               256871               signals
Max msgqueue size         819200               819200               bytes
Max nice priority         0                    0
Max realtime priority     0                    0
Max realtime timeout      unlimited            unlimited            us
```
>磁盘满了，无法再写入core文件

- 打印core堆栈
  - 用gdb查看堆栈。gdb -c core.xxx $bin，$bin是二进制文件的路径，比如php-cgi出core就用$odp_root/php/bin/php-cgi这个路径，hhvm用$odp_root/hhvm/bin/hhvm_bin
  - php Floating point exception一般是加载了系统库的glibc版本错误导致，这往往是因为编译扩展所用的gcc版本和编译php所用的gcc版本（一般是3.4.5）不一致导致
  - hhvm core在HPHP::Extension::ThreadInitModules()，这是因为hhvm 3.0加载了hhvm 2.2的扩展导致的，请选择正确的扩展版本。
  - hhvm core在HPHP::Unit::defCns(), /tmp目录所在的磁盘分区满了会导致这个core


## 进程hang死
表现：进程是存活的，但是不工作

gdb -p $pidattach上去看看hang在什么堆栈上，同样看看每个线程都在做什么

info threads查看线程列表，thread 线程号进入某个线程
bt查看线程堆栈

还可以在gdb里面输入continue让它继续执行，一会再Ctrl+C看看在做什么。

## 系统问题
### cpu打满
根据perf工具进行定位。

### 内存泄漏
这种情况下进程工作正常但是占用的内存一直在增长。

- 先确定是否是持续增长，有些程序随着压力的增大内存占用会增大，这是正常的，如果在压力恒定情况下，内存还一直增长，那可能就是内存泄漏了。
- 确定进程的线程数是否增长，比如对于hhvm来说，有一部分内存占用是和线程数成正比的，如果瞬间并发数过大，可能导致线程数增长。如果线程数不变而内存还一直增长，那可能是内存泄漏。
- 看看内存是连续地上涨，还是跳跃性地增长。如果是跳跃性地增长，看看内存发生突变的时间点，是否有某些变更事件（比如上线文件、上线数据），那么内存增长有可能是由这些变更事件触发。
- 工具分析：内存泄漏可以用gperftools工具进行分析，找出泄漏根源。
- 对于hhvm 1.2.3.2版本以上，有更方便的分析方法：
```
ResourceLimit {
 # 内存使用达到1G后，启动memory profiling分析
 MemoryProfilingThreshold = 1000000000
 # 内存达到2G后，dump memory profiling分析结果并重启服务
 MaxRSS = 2000000000
} 
```
- hhvm 内存增长原因
  - 不断include新的php文件，每次新文件上线都会使内存有一定增长
  - 直接加载phar包，而不是解压开来用
  - 使用了eval、create_function等函数，而且每次eval所用的代码都是不一样的，种类会不断增长 (可以设置Eval.EnableDynamicFuncWarn = true，对于这种动态调用会产生相应的warning日志)
  - 使用了正则表达式处理函数，而且每次用的正则表达式都是不一样的，种类会不断增长 (1.2.7.1版本后，可以设置正则表达式缓存大小，设置Preg.PcreCacheMaxSize配置项到一个合理的值（如10000)，当缓存达到该值后，不再缓存正则表达式编译结果，而是使用后就释放)

### fd泄漏
- 可以ls -l /proc/$pid/fd查看进程都打开了哪些fd。
- lsof|grep pid查看socket类fd的具体上下游信息

### 磁盘满
- /tmp分区打满
  - /tmp/phpXXXXX这样的文件，这些文件是php-fpm解析post表单临时生成的，正常情况下会删除，但如果nginx超时断开连接，这些文件不会被删除。解决方法是开启php.ini中ignore_user_abort选项，或者调大nginx超时
  - /tmp/sess_xxx这样的文件，这些文件是记录session信息的，可以通过session_set_save_handler实现自己的session存储逻辑，比如可以将session保存到分布式cache或者mysql中。
- /home分区打满
  - 一般是日志写太多，或者出core出太多导致/home分区满。
