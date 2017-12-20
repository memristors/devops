# linux 故障追查

Netflix 性能工程团队总结了在故障开始的60s如何检查linux，获取资源利用（cpu、内存、IO、网络）情况以及进程运行情况。

## uptime
```
uptime
12:36:12 up 884 days, 11:53,  3 users,  load average: 1.02, 1.09, 1.30
 ```
主要用来查看负载，查看1min、5min、15min的情况，这三个数字能告诉我们负载在时间线上是如何变化的。

负载如何理解？负载是一段时间内正在使用和等待使用CPU的平均任务数。CPU的工作负载越大，代表CPU必须要在不同的工作之间进行频繁的工作切换。

## dmesg|tail
显示linux内核的环形缓冲区信息，我们可以从中获得诸如系统架构、cpu、挂载的硬件，RAM等多个运行级别的大量的系统信息，可以通过dmesg发现oom与网络丢包等蛛丝马迹。

## vmstat
一般vmstat工具的使用是通过两个数字参数来完成的，第一个参数是采样的时间间隔数，单位是秒，第二个参数是采样的次数
```
vmstat 1
procs -----------memory---------- ---swap-- -----io---- --system-- ----cpu----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in    cs us sy id wa
 4  0      0 4448812 638884 81259952    0    0     0    89    0     0  4  2 93  0
 2  0      0 4450376 638884 81260192    0    0     0    40 58804 162513 10 14 76  0
 1  0      0 4452532 638884 81260448    0    0     0    32 57418 161383 10 15 76  0
 7  0      0 4446916 638884 81260720    0    0     0    32 59499 162079  9 15 76  0
 3  0      0 4451836 638884 81260904    0    0     0  2640 62364 164539  8 12 81  0
```
- r 表示运行队列(就是说多少个进程真的分配到CPU),当这个值超过了CPU数目，就会出现CPU瓶颈了
- b 表示阻塞的进程
- swpd 虚拟内存已使用的大小,如果大于0，表示你的机器物理内存不足了
- free   空闲的物理内存的大小
- buff   Linux/Unix系统是用来存储，目录里面有什么内容，权限等的缓存
- cache cache直接用来记忆我们打开的文件,给文件做缓冲
- si  每秒从磁盘读入虚拟内存的大小,如果这个值大于0，表示物理内存不够用或者内存泄露了
- so  每秒虚拟内存写入磁盘的大小
- bi  块设备每秒接收的块数量,反应写操作的情况
- bo  块设备每秒发送的块数量，反应读操作的情况
- in 每秒CPU的中断次数，包括时间中断
- cs 每秒上下文切换次数，这个值要越小越好，太大了，要考虑调低线程或者进程的数目。上下文切换次数过多表示你的CPU大部分浪费在上下文切换，导致CPU干正经事的时间少了，CPU没有充分利用，是不可取的。
- us 用户CPU时间
- sy 系统CPU时间
- id  空闲 CPU时间
- wa 等待IO CPU时间，等待I/O的情形肯定指向的是磁盘瓶颈；这个时候CPU通常是空闲的，因为任务被阻塞以等待分配磁盘I/O

## pidstat
pidstat主要用于监控全部或指定进程占用系统资源的情况，如CPU，内存、设备IO、任务切换、线程等。
```
pidstat [option] interval [count]
-p 查看特定进程
-u 查看cpu
-r 查看内存利用率与缺页终端信息
-d 查看磁盘io
-w 上下文切换统计信息
```
命令现实的具体含义通过 ```man pidstat``` 查看


## mpstat
Report processors related statistics

这个命令可以按时间线打印每个CPU的消耗，常常用于检查不均衡的问题。如果只有一个繁忙的CPU，可以判断是属于单进程的应用程序。

## iostat
Report  Central  Processing  Unit  (CPU)  statistics  and input/output statistics for devices, partitions and  network  filesystems (NFS).

```
      iostat
             Display  a  single  history  since  boot report for all CPU and
             Devices.

      iostat -d 2
             Display a continuous device report at two second intervals.

      iostat -d 2 6
             Display six reports at two second intervals for all devices.

      iostat -x hda hdb 2 6
             Display six reports of extended statistics at two second inter-
             vals for devices hda and hdb.

      iostat -p sda 2 6
             Display  six reports at two second intervals for device sda and
             all its partitions (sda1, etc.)
```

## free
内存查看

## sar
Collect, report, or save system activity information

```
# sar -n dev 2 3
01:17:51 PM     IFACE   rxpck/s   txpck/s    rxkB/s    txkB/s   rxcmp/s   txcmp/s  rxmcst/s
01:17:52 PM        lo    357.00    357.00     98.96     98.96      0.00      0.00      0.00
01:17:52 PM     xgbe0    180.00    156.00     25.48     15.02      0.00      0.00      0.00
01:17:52 PM     xgbe1      0.00      0.00      0.00      0.00      0.00      0.00      0.00
01:17:52 PM      eth0      0.00      0.00      0.00      0.00      0.00      0.00      0.00
01:17:52 PM      eth1      0.00      0.00      0.00      0.00      0.00      0.00      0.00
01:17:52 PM      eth2      0.00      0.00      0.00      0.00      0.00      0.00      0.00
01:17:52 PM      eth3      0.00      0.00      0.00      0.00      0.00      0.00      0.00
01:17:52 PM      usb0      0.00      0.00      0.00      0.00      0.00      0.00      0.00
```

## top
The top program provides a dynamic real-time view of a running system.It can display system summary information as well as a list  of  tasks currently being managed by the Linux kernel.

<span style='color:red;font-size:x-large';>有不懂的选项就问man命令</span>
