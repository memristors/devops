# 跨站请求伪造
## CSRF漏洞【低危】
### 原理概述
跨站请求伪造（cross site request forgery简称CSRF）是一种利用用户的身份对网站进行某种操作的漏洞，用户自己察觉不到这种操作，但操作请求是以用户的身份发出去的。网站是通过cookie来识别用户的，比如当用户成功在A网站进行身份验证之后浏览器就会得到一个标识其身份的cookie，只要不关闭浏览器或者退出登录，以后访问这个A网站会带上这个cookie。如果这期间用户访问了某个不受信任的第三方站点B，而该站点包含了对A站点某个接口进行请求的代码，那么这个请求就会以用户的身份发出去，而用户自己并不知情
### 危害
1.以用户的身份在用户不知情的情况下执行用户所不愿意执行的操作，比如：修改个人资料，修改管理密码，进行银行转账，操纵用户恶意刷票等等
···
### BadCase样例
原理图如下：
![](/images/csrf.png)

```php
/**
假设本程序为vul.php，CurrentUser()为获取当前用户标识，以下同
程序直接接受传过来的两个密码值，对比相等就修改当前用户的密码为新密码
黑客可以构造攻击代码为：
<img src="http://server/vul.php?change=1&password_new=123&password_conf=123">
并将此代码嵌入一个HTML页面中，只要登入了web应用的用户访问该页面，他的密码就会在其不知情
的情况下被改成123
**/
<?php
if( isset( $_GET[ 'Change' ] ) ) {
    $pass_new  = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];
    if( $pass_new == $pass_conf ) {
        $pass_new = mysql_real_escape_string( $pass_new );
        $pass_new = md5( $pass_new );
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . CurrentUser() . "';";
        $result = mysql_query( $insert ) or die( '<pre>' . mysql_error() . '</pre>' );
        echo "password changed";
    }
    else {
        echo "password did not match";
    }
    mysql_close();
}
?>
```
### 修复建议
<font color='red'>
注：修复建议中，第一条为推荐使用方案，第二，三条仅为辅助方案
</font>

1.<B>首选方式是用随机token</B>，CSRF攻击能够成功的<B>关键因素是网络请求的每个参数都是可预知的</B>，只要打破这种可预知性，就能防御这种攻击。因此可以在每次请求的时候带上一个随机的参数，即token，又因为CSRF攻击是用到了浏览器的同源策略，默认会带上的请求参数是get列表，cookie等，因此token又要放在默认带不走的位置。同时，token也应该保证客户端不可伪造，所以其生成逻辑要在服务端进行，且生成算法要足够随机，无法猜解。综上，可总结防御措施如下：
- 关键性的操作一律使用POST方式提交数据，同时在表单和服务端session中都要存放token
- 用户数据提交过来之后检查所提交的token是否和服务端存放的token一致，若不一致，则应视为发生了CSRF攻击，该次请求无效。
- 【本项可选，不做强制要求】另外使用token时也要注意一次性原则，即某个token一旦被提交到服务端，则应生成一个新token给用户，相同的token再次提交应视为无效




2.CSRF的攻击过程，通常是在用户不知情的情况下发出了网络请求，而验证码则强制要求用户与网站进行交互才能完成最终的请求，因此验证码能相对有效的防御CSRF攻击。使用验证码时要注意如下几点：
- 在采用验证码时必须确保验证码的一次性使用，即某个验证码一旦被提交则失效，如果再次提交则应视为无效。
- 此外验证码也有弊端，考虑到用户体验，不可能给所有的操作都加上验证码，因此验证码也只能作为一种辅助手段进行防御CSRF

3.对于每个请求，校验其refer，但这只能作为辅助手段，因为refer一来可以被伪造，二来在很多业务场景下也浏览器也不会发送refer，样例如下
```php
//检查refer，这里以test.baidu.com为例，如果不是test.baidu.com域下过来的请求，则一律禁止
if ($_SERVER['HTTP_REFERER']!=='http://test.baidu.com') {
    die('not allowed')
}
```
