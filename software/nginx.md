# nginx

## 特性
- 模块化设计，扩展模块丰富
- 低内存消耗、高并发
- 事件驱动
- 高可靠性，master、worker架构
- 热更新配置、平滑升级

## 功能
- 静态资源web服务器
- 基于域名的虚拟主机
- http、https、smtp、pop3、tcp、udp反向代理
- 负载均衡
- 页面缓存
- 支持代理fastcgi、uwsgi应用服务器
- 支持gzip、expires
- url rewrite
- 路径别名
- 基于ip、用户访问控制
- 支持访问速度、并发限制

## 架构
![](/images/nginxarch.png)

### master process
- 与外界通信，接受信号，nginx重启、停止、重载配置、平滑升级
- 通过发送signal对work进程进行管理
- 读取nginx配置文件并验证有效性，管理和结束工作进程
- 监听端口

### work process
- 接受客户端请求，将请求转发给各个模块处理
- 系统io调用，获取响应数据发送给客户端
- 数据缓存管理
- 接受主进程指令例如重启、关闭

### cache
- 缓存索引重建
- 缓存索引管理

## nginx模型
- prefork
- work
- event

## nginx vs apache
- nginx更轻量级，占用内存更少
- nginx并发更高，单机支持10w qps，nginx处理请求异步非阻塞，apache阻塞
- nginx多进程模式，apache有多进程与多线程两种模式
- apache稳定性更高
- 网络io模型不通，aapache采用select,nginx在linux 2.6后采用epoll

## io模型

对于一个network IO (这里我们以read举例)，它会涉及到两个系统对象，一个是调用这个IO的process (or thread)，另一个就是系统内核(kernel)。当一个read操作发生时，它会经历两个阶段：
1. 等待数据准备 (Waiting for the data to be ready)
2. 将数据从内核拷贝到进程中 (Copying the data from the kernel to the process)

IO Model的区别就是在两个阶段上各有不同的情况

- blocking IO
![](/images/blockingio.gif)
>当用户进程调用了recvfrom这个系统调用，kernel就开始了IO的第一个阶段：准备数据。对于network io来说，很多时候数据在一开始还没有到达（比如，还没有收到一个完整的UDP包），这个时候kernel就要等待足够的数据到来。而在用户进程这边，整个进程会被阻塞。当kernel一直等到数据准备好了，它就会将数据从kernel中拷贝到用户内存，然后kernel返回结果，用户进程才解除block的状态，重新运行起来。
<span style="color:red">blocking IO的特点就是在IO执行的两个阶段都被block了</span>

- nonblocking IO
![](/images/noblockingio.gif)
>从图中可以看出，当用户进程发出read操作时，如果kernel中的数据还没有准备好，那么它并不会block用户进程，而是立刻返回一个error。从用户进程角度讲 ，它发起一个read操作后，并不需要等待，而是马上就得到了一个结果。用户进程判断结果是一个error时，它就知道数据还没有准备好，于是它可以再次发送read操作。一旦kernel中的数据准备好了，并且又再次收到了用户进程的system call，那么它马上就将数据拷贝到了用户内存，然后返回。
<span style="color:red">用户进程其实是需要不断的主动询问kernel数据好了没有。</span>

- IO multiplexing
![](/images/multiplex.gif)
>当用户进程调用了select，那么整个进程会被block，而同时，kernel会“监视”所有select负责的socket，当任何一个socket中的数据准备好了，select就会返回。这个时候用户进程再调用read操作，将数据从kernel拷贝到用户进程。
>
> 用select的优势在于它可以同时处理多个connection。如果处理的连接数不是很高的话，使用select/epoll的web server不一定比使用multi-threading + blocking IO的web server性能更好，可能延迟还更大。select/epoll的优势并不是对于单个连接能处理得更快，而是在于能处理更多的连接。
  - select:目前几乎在所有的平台上支持，其良好跨平台支持也是它的一个优点。select的一个缺点在于单个进程能够监视的文件描述符的数量存在1024的最大限制,对socket进行扫描时是线性扫描，即采用轮询的方法，效率较低,需要维护一个用来存放大量fd的数据结构，这样会使得用户空间和内核空间在传递该结构时复制开销大
  - poll 除了文件描述符数量无最大限制（原理是链表存储fd），其他一样
  - epoll <span style="color:red">2.6内核中提出的，</span>没有最大并发连接的限制，能打开的FD的上限远大于1024，效率提升，不是轮询的方式，不会随着FD数目的增加效率下降，只有活跃可用的FD才会调用callback函数，即Epoll最大的优点就在于它只管你“活跃”的连接，而跟连接总数无关。在用户空间和内核空间共享一片存储区域。
  - 在连接数少并且连接都十分活跃的情况下，select和poll的性能可能比epoll好


- asynchronous IO
![](/images/aio.gif)
>用户进程发起read操作之后，立刻就可以开始去做其它的事。而另一方面，从kernel的角度，当它受到一个asynchronous read之后，首先它会立刻返回，所以不会对用户进程产生任何block。然后，kernel会等待数据准备完成，然后将数据拷贝到用户内存，当这一切都完成之后，kernel会给用户进程发送一个signal，告诉它read操作完成了。
