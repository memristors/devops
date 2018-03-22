## 管理后台对外【高危】
### 原理概述
线上应用的后台管理界面或后台管理的登录可在外网直接访问
### 危害
1. 如果后台管理界面可在外网直接访问，那么黑客可以直接获得网站的后台管理权限，进一步可能导致黑客获取整站控制权甚至是服务器控制权
2. 如果后台管理界面在外网不能直接访问，但管理员登录界面可在外网访问，那么黑客可以尝试破解登录密码，从而登录进入后台
···

### BadCase样例
```
//类似如下链接
https://www..com/admin
http://bbs..com/admin.php
http://test..com/index.php?action=admin&method=login
···
```

### 修复方案
1. 如果管理后台没有对外的需求，那么直接下掉外网权限
2. 管理后台登陆界面处必须要有有效的验证码，且管理员账号禁止使用弱密码
3. 管理后台的路径不要使用常见的目录名（比如：/admin,/manager等）
4. 管理后台的URL路径访问使用IP白名单控制，代码层面和服务器配置层面都需要进行控制
5. 关键性业务需要考虑使用多因素认证（如：除了使用普通了用户名密码外，另加手机验证码登录等措施）

样例如下：
```
//这里以限制phpmyadmin目录只能从内网访问为例

//nginx配置
location ~ ^/phpmyadmin/{
  allow 192.168.0.1/24;
  deny all;
}
//apache配置
<Directory ~ "^/phpmyadmin/">
  Order allow,deny
  Deny from all
  Allow from 192.168.0.1/24
</Directory>
```
代码层面
```php
//本程序只是个简单示例，旨在说明对于非允许范围内的IP，禁止其访问，产品线在具体实施时建议将允许访问的IP范围做成一个配置文件，或者写入数据库
<?php
$whiteIPMin=sprintf('%u',ip2long('192.168.0.1'));
$whiteIPMax=sprintf('%u',ip2long('192.168.0.254'));
if(isset($_SERVER))
{
  $tmpIP=sprintf("%u",ip2long($_SERVER['REMOTE_ADDR']));
  if(!($tmpIP>=$whiteIPMin&&$tmpIP<=$whiteIPMax))
  {                
    die('not allowed');
  }    
}
?>
```
