## 文件操作类漏洞【高危】
### 原理概述
通常编程语言都会提供一组用于操作文件的api（比如：打开文件，读取，写入，删除等等）以便开发人员通过程序去操作硬盘上的资源，这些api在给开发者带来便利的同时，也给程序自身带来了安全风险，如果这些api操作的对象是用变量代表的，而这些变量又是从外界传入的，就可能存在文件操作类的漏洞。
### 危害
1. 造成敏感文件内容泄露，如：读取任意文件内容，下载任意文件...
2. 删除任意文件，破坏web应用甚至是服务器文件系统，导致拒绝服务
3. 在服务器上写入恶意代码，使得黑客拿到网站控制权甚至是服务器控制权


### BadCase样例
涉及到的函数主要有：``file_get_contents()`` ``highlight_file()`` ``fopen()`` ``readfile()`` ``fread()`` ``fgetss()`` ``fgets()`` ``parse_ini_file()`` ``show_source()`` ``file()`` ``header()`` 等等
<B>请注意：任何操作文件的API都有可能导致漏洞</B>

BadCase样例1:

```php
/**
本例中封装的这个函数通过file_get_contents函数去获取由GET方式指定的URL所指向的内容
但是该Url未经检查，不可信任，黑客可以提交url=../../../../../../etc/passwd
来读取/etc/passwd中的内容，也可以提交url=../../../config/dbcon.php来读取程序
源代码
**/
public function get_keyword()
{
  $url=$_GET['url'];
  $res=@file_get_contents($url);
  if(CHARSET!='UTF-8')
  {
    $res=iconv('UTF-8',CHARSET,$res);
  }
  echo $res;
}
```
BadCase样例2:

```php
/**
lan,filename,dir,file这些参数都是由外界传入且都未经检查
黑客可以提交:
lan=chinese&dir=whatever&filename=../../..index.php&file=Li4vLi4vLi4vaW5kZXgucGhw
从而可以下载到index.php文件，造成程序源码泄露，通过不断变换提交的参数，甚至可以把整站程序
都下载下来
**/
$language=$_GET['lan'];
if($_GET['filename']!="")
{
  $filename=$_GET['filename'];
}
$realname=base64_decode($_GET['file']);
if($filename==$realname)
{
  $allowfile="../paper/$language/".$_GET['dir']."/$filename";
  if(file_exists($allowfile))
  {
    header("Content-type:application");
    header("Content-Disposition:attachment;filename=".$filename);
    readfile($allowfile);
  }
}
```
BadCase样例3:
```php
/**
变量path和code的值都是由外界传入，未经检查，黑客可以利用类似于firefox的cookiemanager
等插件修改file_path=hack.php，然后以GET方式传参:code=<?php eval($_POST[1]);?>
即可在服务器上写入恶意代码从而控制服务器
**/
$path=$_COOKIE['file_path'];
$code=stripcslashes($_GET['code']);
if($action=='edit_code')
{
  if(file_put_contents(ROOT.$path,$code))
  {
    Message::display("修改成功");
  }
}
```
BadCase样例4:
```php
/**
如上几例，要删除的对象名是从外界传入且未经检查直接就进行删除操作
黑客可以利用../来跳转到任意目录下去删除任意文件
**/
if($action=='del')
{
  @unlink('../tmp/data/'.$_GET['filename']);
}
```
### 修复建议
进行漏洞修复时必须明确以下几点：
- 对于"获取文件内容并展示给用户"或者"文件下载"这类的功能，只允许用户读取某些静态文件的内容，文件类型要通过文件后缀白名单进行控制
- 绝对禁止使用"../"进行目录跳转
- 对于文件下载&&删除的功能，可被操作的文件应该存放于特定路径下，不在该路径下的文件禁止被下载或删除


修复样例1
```php
public function get_keyword()
{
  $url=$_GET['url'];
  $ext=pathinfo($url,PATHINFO_EXTENSION);
  $name=pathinfo($url,PATHINFO_BASENAME);
  //白名单控制允许读取的文件类型
  $whiteExt=array('jpg','txt','pdf','gif');
  //判断文件类型是否合法
  if(!in_array($ext,$whiteExt))
  {
    die("error");
  }

  /**
    判断参数中是否有../，./等字符，如果有则禁止执行。
    同时需要注意：如果程序逻辑中存在对参数进行解码的操作，比如：$url=$_GET['url'];这里GET
    到的是个base64字符串，后续还有$realfile=base64_decode($url);
    那么一定要在解码完毕之后判断参数中是否存在../
  **/
  if(!(strpos($url,"../")===false && strpos($url,"./")===false))
  {
    die("error");
  }
  $res=@file_get_contents($url);
  if(CHARSET!='UTF-8')
  {
    $res=iconv('UTF-8',CHARSET,$res);
  }
  echo $res;
}
```
修复样例2
```php
$filename=$_GET['filename'];
$dir='../tmp/data/';//只有该路径下的文件可被删除
$realFilename=pathinfo($filename,PATHINFO_BASENAME);
$targetDelFile=$dir.$realFilename;
if(!file_exists($targetDelFile))
{
   die("error");
}
if($action=='del')
{
  @unlink($targetDelFile);
}
```
