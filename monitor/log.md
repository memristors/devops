# 日志规范

## 日志模型
![img](/images/logmodel.png)

日志是描述系统行为的重要手段. 棱镜内部, 日志被作为系统监控, 问题定位, 数据分析的重要工具。

我们可以把整个系统看成多个模块(module)构成, 每个模块是一个可单独运行的实体, 比如ODP环境中的一个实例, 或JAVA/C++中的一个process. 模块间以Client/Server的模式通信, 一个模块会以RPC的形式调用另外一个模块, 在这种情况下, 调用RPC的为client, 被调用的模块为server. 因此系统中一般存在三种形式的日志:

- Server Log server端产生的日志. 该日志往往不包含业务相关信息. 只包含该模块入口的基本信息.
- UI Log 业务进程产生的日志, 业务进程将调试信息, 业务特定信息, 通过UI Log的方式打印.
- Client Log 调用RPC的日志, 一般包含RPC结果, 耗时, 协议等信息.


Server Log 和 Client Log 主要用来分析模块间依赖相关的功能, 如日志定位, 远程调用失败. 而UI Log主要用来对接口进行监控, 数据分析等, 包括cost监控, qps监控, 错误率监控等.

|      |UI log|client log|server log|
| :--| :--|:--|:--|:--|
| cost |y|n| y|
| qps |y|n| y|
| 上下游串联 |y|y| y|
| 错误率监控 |y|n| n|

## ui日志规范
建议每个请求一条NOTICE(INFO)级别日志. 在请求结束打印. 如不能提供唯一一条, 也需要提供一条能通过正则匹配的NOTICE(INFO)级别日志. 非预期结果用WARNING级别. 导致系统不可用错误使用FATAL级别日志.

格式: {level}: {timestamp} [ optime={optime} product={product} subsys={subsys} module={module} logId={logId} key={value} … ]

<table class="tablesorter tablesorter-default">

<tbody>
<tr>
<td style="text-align:left">level</td>
<td style="text-align:left">日志级别</td>
<td style="text-align:left">是</td>
<td style="text-align:left">string</td>
<td style="text-align:left">NOTICE</td>
<td>ODP框架: NOTICE/WARNING/FATAL, Java框架 INFO/WARNING/FATAL</td>
</tr>
<tr>
<td style="text-align:left">timestamp</td>
<td style="text-align:left">时间戳</td>
<td style="text-align:left">是</td>
<td style="text-align:left">YY-MM-DD hh: mm: ss/MM-DD hh: mm: ss</td>
<td style="text-align:left">09-09 14:26:32</td>
<td></td>
</tr>
<tr>
<td style="text-align:left">logId</td>
<td style="text-align:left">logid</td>
<td style="text-align:left">是</td>
<td style="text-align:left">string</td>
<td style="text-align:left">1591985286</td>
<td>字段名现阶段不统一, 建议统一使用logid</td>
</tr>
<tr>
<td style="text-align:left">optime</td>
<td style="text-align:left">记录日志时间</td>
<td style="text-align:left">是</td>
<td style="text-align:left">second.ms</td>
<td style="text-align:left">1441779992.210</td>
<td></td>
</tr>
<tr>
<td style="text-align:left">product</td>
<td style="text-align:left">产品</td>
<td style="text-align:left">是</td>
<td style="text-align:left">string</td>
<td style="text-align:left">metis</td>
<td></td>
</tr>
<tr>
<td style="text-align:left">subsys</td>
<td style="text-align:left">子系统</td>
<td style="text-align:left">是</td>
<td style="text-align:left">string</td>
<td style="text-align:left">radar</td>
<td></td>
</tr>
<tr>
<td style="text-align:left">module</td>
<td style="text-align:left">模块</td>
<td style="text-align:left">是</td>
<td style="text-align:left">string</td>
<td style="text-align:left">tester</td>
<td></td>
</tr>
<tr>
<td style="text-align:left">uri</td>
<td style="text-align:left">当前页面url</td>
<td style="text-align:left">请求级别日志必须</td>
<td style="text-align:left">string</td>
<td style="text-align:left">%2Fusercenter%2Fapi%2Fphone</td>
<td></td>
</tr>
<tr>
<td style="text-align:left">refer</td>
<td style="text-align:left">前链url</td>
<td style="text-align:left">否</td>
<td style="text-align:left">string</td>
<td style="text-align:left">-</td>
<td></td>
</tr>
<tr>
<td style="text-align:left">cost</td>
<td style="text-align:left">请求耗时(ms)</td>
<td style="text-align:left">请求级别日志必须</td>
<td style="text-align:left">int</td>
<td style="text-align:left">45</td>
<td></td>
</tr>
<tr>
<td style="text-align:left">retErrno</td>
<td style="text-align:left">返回错误码</td>
<td style="text-align:left">请求级别日志必须</td>
<td style="text-align:left">int</td>
<td style="text-align:left">0</td>
<td>0正常, 非0错误码</td>
</tr>
<tr>
<td style="text-align:left">errDetail</td>
<td style="text-align:left">描述信息</td>
<td style="text-align:left">请求级别日志必须</td>
<td style="text-align:left">string</td>
<td style="text-align:left">format error</td>
</tr>
</tbody>
<thead><tr class="tablesorter-headerRow">
<th style="text-align: left; user-select: none;" data-column="0" class="sortableHeader" tabindex="0" unselectable="on"><div class="tablesorter-header-inner">字段</div></th>
<th style="text-align: left; user-select: none;" data-column="1" class="sortableHeader" tabindex="0" unselectable="on"><div class="tablesorter-header-inner">描述</div></th>
<th style="text-align: left; user-select: none;" data-column="2" class="sortableHeader" tabindex="0" unselectable="on"><div class="tablesorter-header-inner">是否必须</div></th>
<th style="text-align: left; user-select: none;" data-column="3" class="sortableHeader" tabindex="0" unselectable="on"><div class="tablesorter-header-inner">格式</div></th>
<th style="text-align: left; user-select: none;" data-column="4" class="sortableHeader" tabindex="0" unselectable="on"><div class="tablesorter-header-inner">举例</div></th>
<th data-column="5" class="sortableHeader" tabindex="0" unselectable="on" style="user-select: none;"><div class="tablesorter-header-inner">说明</div></th>
</tr></thead><thead>

</thead></table>
> NOTICE: 09-09 14:26:32 usercenter * 45785 [logid=1591985286 filename=/home/work/orp/php/phplib/saf/base/Log.php lineno=28 errno=0 optime=1441779992.210 client_ip=10.202.147.21 local_ip=10.202.68.39 product=nuomi subsys=usercenter module=usercenter uniqid=4214836626 cgid=0 uid=0 passUid=1643578291 bduss= cuid= tn= channel= s= appid= version= ip= pageService=Service_Page_Setting_Phone redisCostUsercenter=0 retErrorNo=0 un= mobilephone= email= baiduid= url=%2Fusercenter%2Fapi%2Fphone refer= uip=10.202.147.21 ua=RAL%2F2.0.2.1%20%28internal%20request%29 host=sh.api.int.nuomi.com cost=2 errmsg=]

## server log
```
logid
spanid
status
host
server_addr
server_port
client_addr
request
msec
request_time
```
