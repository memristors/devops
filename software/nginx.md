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
- 网络io模型不通，aapache采用select,nginx在linux 2.6后采用epool
