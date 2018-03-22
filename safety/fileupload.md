## 上传漏洞【高危】
### 原理概述
应用程序因为业务需要，提供了上传文件的功能，但是在上传点处对所上传的文件安全检查不够严格甚至不做检查，导致黑客可以上传任意文件，进而获取网站控制权甚至是服务器控制权。
### 危害
1. 上传的文件若为web脚本文件，服务器的web容器解释并执行了黑客上传的脚本，导致黑客直接获取网站控制权
2. 上传文件为crossdomain.xml，则黑客能控制flash在该域下的行为
3. 上传文件为病毒，木马等，黑客可以诱骗用户或者管理员下载执行
···

### BadCase样例
BadCase样例1:
```php
/**
对上传的文件不做任何检查，黑客可以直接上传任意文件，最常见的利用方式就是上传一个具有文件
操作功能的脚本，直接获得网站控制权
**/
if($_FILES)
{
  $dest="./upfilestore/";
  move_uploaded_file($_FILES['upfile']['tmp_name'],$dest.$_FILES['upfile']['name']);
}
```
BadCase样例2:
```php
/**
本例看似对上传的文件做了类型检查，非图片类型的则不允许上传
但$file['type']是从客户端获取而来的数据，黑客可以将数据包截获下来更改http header中
content-type的值来绕过检查
**/
$dest="./upfilestore/";
$uptypes=array(
'image/jpg',
'image/jpeg',
'image/png',
'image/gif'
);
$file=$_FILES['upfile'];
if(!in_array($file['type'],$uptypes))
{
  die("invalid types!");
}
else
{
  move_uploaded_file($file['tmp_name'],$dest.$file['name']);
}
```
BadCase样例3:
```php
/**
本例使用了黑名单来检查上传的文件名后缀，如果是黑名单中的类型则禁止上传
但是黑名单是一种很不好的思想，存在被绕过的风险
本例中黑客可以上传xxx.php4,xxx.php3,xxx.asa,xxx.pl等类型的文件都可以绕过检查
**/
function getExt($filename)
{
  return substr($filename,strripos($filename,".")+1);
}
$disAllowExt=array('php','asp','aspx','jsp','exe');
$fileExt=strtolower(getExt($_FILES['upfile']['name']));
if(in_array($fileExt,$disAllowExt))
{
  die("disallowed type");
}
else
{
  $dest="./upfilestore/";
  move_uploaded_file($_FILES['upfile']['tmp_name'],$dest.$_FILES['upfile']['name']);
}
```
BadCase样例4
```php
/**
在PHP版本<5.3.4并且magic_quotes_gpc=off的情况下，即使是使用白名单检测文件名后缀也是
存在被绕过的风险的
黑客可以提交hack.php\0.jpg, 其中\0代表0x00，这样能绕过文件名后缀的检查，也能由于0x00的
截断作用使得最终保存在服务器上的为hack.php

本例中黑客可以提交file=hack.php%00,然后上传一个后缀为jpg的文件，最终生成的就是hack.php文件
**/

error_reporting(0);
if(isset($_FILES))
{
    $ext_arr = array('flv','swf','mp3','mp4','3gp','zip','rar','gif','jpg','png','bmp');
    $file_ext = substr($_FILES['upfile']['name'],strrpos($_FILES['upfile']['name'],".")+1);
    if(in_array($file_ext,$ext_arr))
    {
        $tempFile = $_FILES['upfile']['tmp_name'];
        $targetPath = $_SERVER['DOCUMENT_ROOT'].$_REQUEST['file'].rand(10, 99).date("YmdHis").".".$file_ext;
        if(move_uploaded_file($tempFile,$targetPath))
        {
            echo 'upload success'.'<br>';
        }
        else
        {
           echo("upload failed!");
        }
    }
else
{
    echo("upload failed");
}
}
```
### 修复建议
1. 对于上传的文件，一定要做文件类型检查，且一定要在服务端做检查，如果只在前端用JS检查则完全可以被绕过
2. 上传之后的文件，需要对文件重命名为一个随机文件名
3. 如果PHP版本小于5.3.4则需要对上传的文件名进行转义，防止被截断上传

样例如下：
```php
$file=$_FILES['upfile'];
//检查PHP版本，如果小于5.3.4则要检查magic_quotes_gpc选项的值，如果该值关闭，则要对上传
//的文件名转义
if(PHP_VERSION<'5.3.4')
{
  if(!ini_get('magic_quotes_gpc'))
  {
    $file['name']=addslashes($file['name']);
  }
}

//白名单控制允许上传的文件名后缀
$allowedExt=array('jpg','gif','jpeg','pdf');
$fileExt=pathinfo($file['name'],PATHINFO_EXTENSTION);
if(!in_array($fileExt,$allowedExt))
{
  die('disallowed type');
}
else
{
 $dest='./upfilestore/';
 //将文件重命名一个随机文件名
 $filename=md5(rand()).date("YmdHis").$fileExt;
 move_uploaded_file($file['tmp_name'],$dest.$filename);
}
```
4.如果只允许上传图片类型的文件，那么可以使用PHP的GD库对上传的文件的内容做二次渲染，从而可以剔除文件内容中非图片的数据，防止黑客在正常图片中注入恶意代码
样例如下：
首先需要在PHP.ini中设置启用GD库的扩展，找到``extension=php_gd2.dll``将其前面的分号(;)去掉即可
```
; Windows Extensions
; Note that ODBC support is built in, so no dll is needed for it.
; Note that many DLL files are located in the extensions/ (PHP 4) ext/ (PHP 5)
; extension folders as well as the separate PECL DLL download (PHP 5).
; Be sure to appropriately set the extension_dir directive.
;
;extension=php_bz2.dll
extension=php_curl.dll
;extension=php_fileinfo.dll
extension=php_gd2.dll
```
代码如下：
```php
$file=$_FILES['upfile'];
$dest='./upfilestore/'; //存放上传文件的路径，各产品线根据自己的实际情况进行设置
//检查PHP版本，如果小于5.3.4则要检查magic_quotes_gpc选项的值，如果该值关闭，则要对上传
//的文件名转义
if(PHP_VERSION<'5.3.4')
{
  if(!ini_get('magic_quotes_gpc'))
  {
    $file['name']=addslashes($file['name']);
  }
}

//白名单控制允许上传的文件名后缀，这里只允许上传图片
$allowedExt=array('jpg','gif','jpeg');
$fileExt=pathinfo($file['name'],PATHINFO_EXTENSTION);
if(!in_array($fileExt,$allowedExt))
{
  die('disallowed type');
}
else
{
 if($fileExt=='jpg'||$fileExt=='jpeg')
 {
   $ext='jpeg';
 }
 else
 {
   $ext='gif';
 }
 //重新渲染图片内容，这里默认采用原始大小，因此不做截取操作，各产品线可根据需要自行截取大小
 $createFun='imagecreatefrom'.$ext;
 $newimageFun='image'.$ext;
 $im=$createFun($file['tmp_name']);
 //给文件重命名一个随机文件名
 $filename=md5(rand()).date("YmdHis").$ext;
 //保存文件到指定位置
 $newimageFun($im,$dest.$filename);
 //释放内存
 imagedestroy($im);
}
```
