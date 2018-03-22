## 任意URL Redirect【低危】
### 原理概述
URL重定向(即：Url redirect)是指将网址指向一个新的URL地址，很多业务场景中都会有这样的功能，这项功能本身是没有问题的，有问题的是对于要重定向的目标网址如果不做任何检查而造成任意的重定向的话，就有可能被黑客利用进行一些恶意的行为（详见危害）
### 危害
1.重定向到第三方钓鱼网站，对用户进行网络钓鱼，欺诈等攻击
2.由于发起请求的起始域是百度，而跳转的目的域又是不做检查的，所以可被用于传播第三方有危害性的URL
3.重定向到挂马页面攻击用户浏览器，盗号
···
### BadCase 样例
```php
<?php
/*假设本程序名为redirect.php，www.evil.com是黑客控制的网站
重定向的URL没做任何检查，黑客可以构造redirect.php?url=http://www.evil.com然后诱骗普通
网名点击该链接重定向到黑客控制的网站上，从而进行进一步的恶意操作
*/
$url=$_GET['url'];
header("Location:$url");
?>
```
### 修复建议
1.校验refer，检查参数传递的来源可以有助于保证重定向的目的URL地有效性，样例如下：
```php
<?php
/*
比如，redirect.php是在www.baidu.com上，那么正常的重定向的链接应该是www.baidu.com/redirect.php?url=http://www.somedomain.com，而如果refer不是baidu域，而是一个第三方域，比如a.com，那么这个重定向的目标URL，其可信度也是不高的

本例为限制只能由www.baidu.com发起重定向的功能，所以检查refer是否是www.baidu.com如果不是
则一律认为重定向的目标URL不可信
*/
$url=$_GET['url'];
$refer=parse_url($_SERVER['HTTP_REFERER']);
if($refer['host'!='www.baidu.com'])
{
    die('insecure!');
}
else
{
    header("Location:$url");
}
?>
```
2.很多情况下浏览器是不发送refer的，考虑到这种情况，校验refer则只能作为一种辅助手段，更为严谨的方案是使用白名单的方法进行检验，样例如下
```php
//允许跳转的目的域白名单，这里以www.baidu.com,image.baidu.com,www.nuomi.com为例，各产品线可视自己的实际情况进行修改
$whiteDest=array('www.baidu.com','image.baidu.com','www.nuomi.com');
//允许跳转的目的域协议白名单，通常情况下只允许HTTP和HTTPS协议
$protocolwhitelist=array('http','https');
$url=$_GET['url'];
$tmpUrl=parse_url($url);
$flag=1;//标志位，$flag=0表示外界传入的URL是不可信的，程序要内部处理后跳转到修改后的url，$flag=1表示外部传入的url可信，可以直接跳转
if(!in_array($tmpUrl['scheme'],$protocolwhitelist))
{
  $defaultProtocol='http://';//如果外界传入的url参数不是Http或者https协议，则强制修改为http协议
  $flag=0;
}
if(!in_array($tmpUrl['host'],$whiteDest))
{
   $defaultDest='www.baidu.com';//如果外界传入的url参数其目的域不在白名单中，则强制修改为跳转到www.baidu.com，各产品线可根据自己的实际情况进行调整
   $flag=0;
}
if($flag==0)
{
  $destUrl=$defaultProtocol.$defaultDest;
}
if($flag==1)
{
  $destUrl=$url;
}
//执行跳转
header("Location:$destUrl");
```
