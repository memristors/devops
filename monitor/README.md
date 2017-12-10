## 监控衡量指标
监控就4个字（全，少，准，快）
- 全是该有的监控必须有不能丢；
- 少是报警量必须少，多了就是狼来了；
- 准是报出来必须真有问题不能误报；
- 快是异常可以快速报出来

## 监控工具
- 小公司/ 创业团队：< 500台服务器规模,开源方案：Zabbix、Nagios、Cacti
![](/images/monitortool.jpg)
- 云服务提供商：监控宝、oneAlert等
- BAT级别：> 10万台服务器,投入人力，内部自研
  - 腾讯蓝鲸：logstash，kafka，storm，Elasticsearch（tsdb）
  - 美团：Spark Streaming,kafka, Elasticsearch
  - 小米（Open-Falcon）：自研agent,transfer,Aggregator,judge,graph
  - 百度：logstream,kafka,storm,hbase（tsdb）, Elasticsearch

## 监控体系建设
- 监控指标的全（覆盖完整） 和 准（准确有效）
- 报警收敛
- 监控工具优化


## 监控标准化
### 监控标准应该包含什么
- 规定应该加什么监控
- 规定应该如何设置报警策略
- 规定应该如何设置报警通告
- 规定应该如何定位问题
- 规定应该如何处理报警

### 监控如何标准化
- 制定监控标准
- 开发自动化监控添加和管理的系统或工具
- 开发监控工作优劣的评估工具（覆盖度、细致度、正确性等）
- 例行评估，产出报表和改善建议

下面主要讲解如何保证监控完整性和监控有效性。
