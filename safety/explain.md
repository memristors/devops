## 解析漏洞【高危】
### 原理概述
所谓解析漏洞，即web容器对于文件的内容没有按照预期的方式进行解析，比如将.jpg文件按照PHP代码去解析，在这种情况下就可使得黑客通过上传一个.jpg文件就能获取网址控制权，进一步可能获取服务器控制权并渗透内网，公司产品线上比较常见的解析漏洞有两类，即nginx解析漏洞和apache解析漏洞，现分述如下：

#### Apache解析漏洞
apache如果以module方式运行PHP的话，对于文件名的解析是从后向前解析的，一直遇到一个apache"认识"的文件类型为止，比如：``hack.php.xxx.sss.helloworld``因为其中的``.helloworld`` ``.sss`` ``.xxx``都是黑客随手写的后缀，apache肯定是不认识的，所以会一直从后向前遍历到``.php``，然后将其作为一个php文件进行解析，而apache到底认识哪些后缀的文件，是在apache的conf/mime.types文件中定义的。

#### Nginx解析漏洞

Nginx以Fast-Cgi方式运行PHP时，对于任意的后缀名文件，只要加上``/x.php``（即使这个x.php并不存在）那么也会将文件作为PHP文件解析，比如``http://www.baidu.co/logo.png/1.php``就算1.php不存在，logo.png中的内容也会被当作PHP代码运行，此时会大大降低黑客的攻击门槛，因为只需要上传含有php代码的图片文件（而图片文件一般都是允许上传的）就能在服务器上执行任意的PHP代码。

### 修复建议
1.对于apache的解析漏洞，可以在httpd.conf配置文件中添加以下内容来阻止外部访问这类文件
```
<Files ~ "\.(?i:ph.)">
Order Allow,Deny
Deny from all
</Files>
```
或者可用如下设置阻止apache解析脚本
```
#本例为禁止upload目录下解析PHP脚本
<Directory ~ "/upload">
 Options FollowSymLinks
 AllowOverride None
 Order allow,deny
 Allow from all
 php_flag engine off
</Directory>
```
也可以在不想解析PHP的目录下面创建.htaccess文件，里面加入如下代码即可
```
php_flag engine off
```
2.对于Nginx的解析漏洞，可以关闭php.ini中的cgi.fix_pathinfo选项
```
cgi.fix_pathinfo=0
```
或者做如下配置，禁止访问特定目录下的脚本文件
```
#本例为禁止访问/upload目录下的脚本
location ~ ^.*/upload/.*\.(ph.*)$  {        
          deny all;
}
```
```
#禁止访问如/1.jpg/x.php这样的链接
location ~* /((.*)\.(.*)\/(.*)\.php){
    deny all;
}
```
