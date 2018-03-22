## SQL注入【高危】

### 原理概述：

程序在执行SQL时，SQL语句中的某些参数是从外界获取的，而从外界获取的这些参数没有经过过滤处理，导致在这些参数中加入攻击者自己精心构造的SQL指令时这些指令会被执行。SQL注入根据参数分类，可分为数字型和字符型，两者最大区别在于参数是否被引号(''或者"")封闭。
### 危害：
1. 直接造成数据库中数据泄露
2. 如果数据库连接用户具备高权限，则可能导致黑客直接获取服务器控制权
...

### BadCase 样例:
数字型
```php
$con = mysql_connect("localhost","mysql_user","mysql_pwd");
$id=$_GET['id'];
//字符型为这样：$sql="select username,password from users where uid='$id'";
$sql="select username,userpic from users where uid=".$id;    //参数id是通过GET方式获取的，但是未经过滤就直接拼接入SQL语句了
mysql_query($sql,$con);
```
### 修复建议：

1. 首先对于传入的参数一定要做类型/长度检查，不符合的数据类型以及虽然数据类型符合但是长度异常的数据一律不接受；
2. 针对数字型，要先将接受的参数强制转换为数字再执行SQL；
3. 针对字符型，外界的攻击代码首先需要闭合引号，如果能使得引号闭合失效，则可有效阻止攻击的发生
4. <B><font color='red'>漏洞修复完毕之后一定要注意同类的问题做全线排查</font></B>
修复代码样例如下：

<font color='red'>推荐使用参数化查询或者ORM查询方式，现分述如下：</font>

<B>ORM</B>
一般php框架中均有此功能

<B>参数化查询</B>
首先需要开启pdo和pdo_mysql扩展

```php
//首先进入php软件包的pdo扩展目录中（注：不是PHP的安装目录）
[root@sec /]# cd /tmp/lamp/php-5.3.19/ext/pdo_mysql/
//执行phpize命令，/usr/local/php替换成你的PHP安装目录
[root@sec pdo_mysql]# /usr/local/php/bin/phpize
//执行完phpize后，在pdo_mysql目录中就会出现configure，然后执行配置
//--with-php-config=/usr/local/php/bin/php-config 指定安装 PHP 的时候的配置
//--with-pdo-mysql=/usr/local/mysql/ 指定 MySQL 数据库的安装目录位置
[root@sec pdo_mysql]# ./configure --with-php-config=/usr/local/php/bin/php-config --with-pdo-mysql=/usr/local/mysql/
//编译安装
//安装成功之后会出现一个类似/usr/local/php/lib/php/extension/no-debug-non-zts-时间戳/的目录
[root@sec pdo_mysql]# make && make install
//修改php.ini文件，在Php.ini中加入一行
extension=/usr/local/php/lib/php/extensions/no-debug-non-zts-时间戳/pdo_mysql.so
```
代码样例如下：
```php
$pdo=new PDO("mysql:host=localhost;dbname=database","dbusername","dbpassword");
$id=$_GET['id'];
$query="SELECT username,userpic from users WHERE (id = :uid)";
$statement=$pdo->prepare($query,array(PDO::ATTR_CURSOR=>PDO::CURSOR_FWDONLY));
$statement->bindParam(":uid",$id,PDO::PARAM_STR,3);
$statement->execute();
$result=$statement->fetch(PDO::FETCH_ASSOC)
$statement->closeCursor();
$pdo=null;
```
或者也可以使用mysqli的方式进行查询，样例如下：
```php
<?php
$mysqli = new mysqli($db_host, $db_user, $db_password, $db_name);
$sql = "INSERT INTO `users` (id, name, gender, location) VALUES (?, ?, ?, ?)";
$stmt = $mysqli->prepare($sql);
$stmt->bind_param('dsss', $source_id, $source_name, $source_gender, $source_location);
$stmt->execute();
$stmt->bind_result($id, $name, $gender, $location);
while ($stmt->fetch()) {
    echo $id . $name . $gender . $location;
}
$stmt->close();
$mysqli->close();
?>
```
