## XSS漏洞【存储型：高危，反射型：低危】
### 原理概述
黑客通过利用该种类型的漏洞可以在页面上插入自己精心构造的HTML或Js代码，从而在用户浏览网页时，浏览器执行了黑客所插入的恶意代码进而控制用户浏览器。从效果和稳定性上来区分，可分为反射型XSS和存储型XSS，反射型XSS是直接将恶意代码的执行结果反射给浏览器，也就是说黑客往往需要诱使用户点击一个恶意链接才能发起攻击，而存储型XSS是将恶意代码存储在服务器端，然后再输出给前端页面，任何用户访问该页面都会遭受攻击，具有很强的稳定性。
### 危害
- 窃取用户cookie，从而获取用户隐私或利用用户身份进一步对网站进行操作
- 网络钓鱼，盗取各类用户帐号
- 劫持用户浏览器，从而控制浏览器的行为进行任意操作
- 进行网页挂马
- 强制弹出广告页面，恶意刷流量
- 控制受害者机器向其它目标发起攻击


···
### BadCase样例
样例1
```php
<?php
//反射型，黑客可直接提交name=<script>alert(/xss/)</script>
$name=$_GET['name'];
echo "hello".$name;
?>
```
样例2
```php
//$message通过POST方式获得值，然后存入数据库，所获取的值未经任何安全检查，黑客完全可以提交
//自己精心构造的恶意JS代码，从而造成存储型XSS
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );
    $message = stripslashes( $message );
    $message = mysql_real_escape_string( $message );
    $name = mysql_real_escape_string( $name );
    //这里$message没有经过任何过滤就存入了数据库
   $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );
}
?>
//如果在另一个页面，比如显示评论或者消息的页面，又把之前存入数据库的$message显示出来了，那么就会造成存储型XSS，$message在输出时就会在用户浏览器上执行攻击代码
<?php
echo "user:".$username."<BR>";
echo "comment:$message";  //输出了带有XSS攻击代码的$message，攻击代码会在用户浏览器上执行
?>
```
样例3
```html
<!--DOM型XSS，从效果上看属于反射型XSS，但其形成原因与一般XSS不同，
该类型XSS是由于修改了页面的DOM节点造成的
攻击者可以提交 ' onclick=alert(/xss/)//
-->
<script>
function check(){
var str=document.getElementById("text").value;
document.getElementById("t").innerHTML="<a href='"+str+"'>testLink</a>";
</script>
<div id="t"></div>
<input type='text' id="text" value="">
<input type="button" id="s" value="write" onclick="check()">
```
### 修复建议
1.对于非passport/UC账户体系的，关键性的cookie（如：标识用户登录状态的cookie等，这里用login_in_status_token表示）必须加上httponly属性，样例如下：
```php
//本例为设置cookie有效时长为1小时（即3600秒）
setcookie("login_in_status_token","login_in_status_token_VALUE",time()+3600,"/","baidu.com",false,true);
//如果启用了HTTPS的话，那么应该开启secure标记
setcookie("login_in_status_token","login_in_status_token_VALUE",time()+3600,"/","baidu.com",true,true);
```
2.对cookie加上httponly属性也不能修复xss漏洞，只能缓解xss攻击，要修复XSS漏洞，首先需要做输入检查，因为XSS漏洞和SQL注入类似，攻击者也需要构造一些特殊的字符，而这些特殊字符可能是正常用户不会用到的，所以有必要进行输入检查，样例如下：
```php
<?php
//对输入进行检查，过滤掉存在攻击隐患的字符
function RemoveXSS($val)    {        
        $val = preg_replace('/([\x00-\x08][\x0b-\x0c][\x0e-\x20])/', '', $val);
        $search = "'abcdefghijklmnopqrstuvwxyz';
        $search.= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $search.= '1234567890!@#$%^&*()';
        $search.= '~`";:?+/={}[]-_|\'\\';
        for ($i = 0; $i < strlen($search); $i++) {
            $val = preg_replace('/(&#[x|X]0{0,8}'.dechex(ord($search[$i])).';?)/i', $search[$i], $val);
            $val = preg_replace('/(&#0{0,8}'.ord($search[$i]).';?)/', $search[$i], $val);
        }
        //黑名单，其中为存在攻击隐患的字符，可被用于引入HTML标记或者加载脚本代码
       $ra1 = array('javascript', 'vbscript', 'expression', 'applet', 'meta', 'xml', 'blink', 'link', 'style', 'script', 'embed', 'object', 'iframe', 'frame', 'frameset', 'ilayer', 'layer', 'bgsound', 'title', 'base');
       //黑名单，其中为js的事件处理函数名
      $ra2 = array('onabort', 'onactivate', 'onafterprint', 'onafterupdate', 'onbeforeactivate', 'onbeforecopy', 'onbeforecut', 'onbeforedeactivate', 'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint', 'onbeforeunload', 'onbeforeupdate', 'onblur', 'onbounce', 'oncellchange', 'onchange', 'onclick', 'oncontextmenu', 'oncontrolselect', 'oncopy', 'oncut', 'ondataavailable', 'ondatasetchanged', 'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'onerror', 'onerrorupdate', 'onfilterchange', 'onfinish', 'onfocus', 'onfocusin', 'onfocusout', 'onhelp', 'onkeydown', 'onkeypress', 'onkeyup', 'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onmove', 'onmoveend', 'onmovestart', 'onpaste', 'onpropertychange', 'onreadystatechange', 'onreset', 'onresize', 'onresizeend', 'onresizestart', 'onrowenter', 'onrowexit', 'onrowsdelete', 'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange', 'onselectstart', 'onstart', 'onstop', 'onsubmit', 'onunload');
        $ra = array_merge($ra1, $ra2);
        $found = true;
        while ($found == true) {
            $val_before = $val;
            for ($i = 0; $i < sizeof($ra); $i++) {
                $pattern = '/';
                for ($j = 0; $j < strlen($ra[$i]); $j++) {
                    if ($j > 0) {
                        $pattern .= '(';
                        $pattern .= '(&#[x|X]0{0,8}([9][a][b]);?)?';
                        $pattern .= '|(&#0{0,8}([9][10][13]);?)?';
                        $pattern .= ')?';
                    }
                    $pattern .= $ra[$i][$j];
                }
                $pattern .= '/i';
                $replacement = substr($ra[$i], 0, 2).'<x>'.substr($ra[$i], 2);
                $val = preg_replace($pattern, $replacement, $val);
                if ($val_before == $val) {
                    $found = false;
                }
            }
        }
        return $val;
    }
?>
```
3.对输入进行检查有个很明显的弊端就是处理用户的数据时没有结合渲染页面的HTML代码，因此对语境的理解并不完整，比如如下案例
```php
//$src是用户可控的变量，输出到了script标签的src属性中，这时候用户只需要提交一个很正常的URL
//链接即可，比如http://www.attack.com/evil.js，而这个链接所指向的JS文件就含有黑客写的
//恶意代码，这样就绕过输入检查
$src=$_POST['src'];
echo "<script src=$src></script>";
```
还比如，如果用户输入的是``1+1<5``，这是个完全正常的输入，但是其中的``<``则会在输入检查中被当作敏感字符给过滤掉，所以输入检查虽然有必要，但并不是最好的解决办法。
4.由于输入检查存在种种弊端，而XSS攻击是发生在前端页面上，所以最好的解决办法是做输出检查，以下用``$var``表示用户的数据，它在被输出到前端HTML页面中时，会有若干情况，每种情况都需要根据具体场景进行解决，现分述如下:
- 例1：输出在HTML标签中

```HTML
//这种输出在标签中的变量，如果未做任何处理，都可以直接导致产生XSS
//$var=<script>alert(/xss/)</script>
//或者 $var=<img src=# onerror=alert(/xss/) />
//均能触发黑客所构造的JS代码执行
<div>$var</div>
<a href=#>$var</a>
```
<B>修复方式是对变量做HTMLEncode，样例如下：</B>
```javascript
function HTMLEncode(str){
    var hex = new Array('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f');
    var preescape = str;
    var escaped = "";
    for(var i = 0; i < preescape.length; i++){
        var p = preescape.charAt(i);
        escaped = escaped + escapeCharx(p);
    }

    return escaped;
}                
function escapeCharx(original){
    var found=true;
    var thechar=original.charCodeAt(0);
    switch(thechar) {
        case 10: return "<br/>"; break; //newline
        case 32: return "&nbsp;"; break; //space
        case 34:return "&quot;"; break; //"
        case 38:return "&amp;"; break; //&
        case 39:return "&#x27;"; break; //'
        case 47:return "&#x2F;"; break; // /
        case 60:return "&lt;"; break; //<
        case 62:return "&gt;"; break; //>
        case 198:return "&AElig;"; break;
        case 193:return "&Aacute;"; break;
        case 194:return "&Acirc;"; break;
        case 192:return "&Agrave;"; break;
        case 197:return "&Aring;"; break;
        case 195:return "&Atilde;"; break;
        case 196:return "&Auml;"; break;
        case 199:return "&Ccedil;"; break;
        case 208:return "&ETH;"; break;
        case 201:return "&Eacute;"; break;
        case 202:return "&Ecirc;"; break;
        case 200:return "&Egrave;"; break;
        case 203:return "&Euml;"; break;
        case 205:return "&Iacute;"; break;
        case 206:return "&Icirc;"; break;
        case 204:return "&Igrave;"; break;
        case 207:return "&Iuml;"; break;
        case 209:return "&Ntilde;"; break;
        case 211:return "&Oacute;"; break;
        case 212:return "&Ocirc;"; break;
        case 210:return "&Ograve;"; break;
        case 216:return "&Oslash;"; break;
        case 213:return "&Otilde;"; break;
        case 214:return "&Ouml;"; break;
        case 222:return "&THORN;"; break;
        case 218:return "&Uacute;"; break;
        case 219:return "&Ucirc;"; break;
        case 217:return "&Ugrave;"; break;
        case 220:return "&Uuml;"; break;
        case 221:return "&Yacute;"; break;
        case 225:return "&aacute;"; break;
        case 226:return "&acirc;"; break;
        case 230:return "&aelig;"; break;
        case 224:return "&agrave;"; break;
        case 229:return "&aring;"; break;
        case 227:return "&atilde;"; break;
        case 228:return "&auml;"; break;
        case 231:return "&ccedil;"; break;
        case 233:return "&eacute;"; break;
        case 234:return "&ecirc;"; break;
        case 232:return "&egrave;"; break;
        case 240:return "&eth;"; break;
        case 235:return "&euml;"; break;
        case 237:return "&iacute;"; break;
        case 238:return "&icirc;"; break;
        case 236:return "&igrave;"; break;
        case 239:return "&iuml;"; break;
        case 241:return "&ntilde;"; break;
        case 243:return "&oacute;"; break;
        case 244:return "&ocirc;"; break;
        case 242:return "&ograve;"; break;
        case 248:return "&oslash;"; break;
        case 245:return "&otilde;"; break;
        case 246:return "&ouml;"; break;
        case 223:return "&szlig;"; break;
        case 254:return "&thorn;"; break;
        case 250:return "&uacute;"; break;
        case 251:return "&ucirc;"; break;
        case 249:return "&ugrave;"; break;
        case 252:return "&uuml;"; break;
        case 253:return "&yacute;"; break;
        case 255:return "&yuml;"; break;
        case 162:return "&cent;"; break;
        case '\r': break;
        default:
            found=false;
            break;
    }
    if(!found){
        if(thechar>127) {
            var c=thechar;
            var a4=c%16;
            c=Math.floor(c/16);
            var a3=c%16;
            c=Math.floor(c/16);
            var a2=c%16;
            c=Math.floor(c/16);
            var a1=c%16;
            return "&#x"+hex[a1]+hex[a2]+hex[a3]+hex[a4]+";";        
        }
        else{
            return original;
        }
    }    
}
```
- 例2：在HTML属性中输出

```html
//类似上例，黑客可以提交$var="><script>alert(/xss/)</script><"
<div id="test" name="$var"></div>
```
<B>修复方式同例1，对$var进行HTMLEncode</B>
- 例3：在``<script>``标签中输出

```html
//在<script>标签中输出时，首先要确保输出的变量在引号中，这样黑客必须先闭合引号才能实施XSS攻击
<script>
var a="$var";
</script>
```
<B>修复方式是对变量做javascriptEncode，样例如下：</B>
```javascript
function changeTo16Hex(charCode){
        return "\\x" + charCode.charCodeAt(0).toString(16);
    }
function encodeCharx(original) {

        var found = true;
        var thecharchar = original.charAt(0);
        var thechar = original.charCodeAt(0);
        switch(thecharchar) {
            case '\n': return "\\n"; break; //newline
            case '\r': return "\\r"; break; //Carriage return
            case '\'': return "\\'"; break;
            case '"': return "\\\""; break;
            case '\&': return "\\&"; break;
            case '\\': return "\\\\"; break;
            case '\t': return "\\t"; break;
            case '\b': return "\\b"; break;
            case '\f': return "\\f"; break;
            case '/': return "\\x2F"; break;
            case '<': return "\\x3C"; break;
            case '>': return "\\x3E"; break;
            default:
                found=false;
                break;
        }
        if(!found){
            if(thechar > 47 && thechar < 58){ //数字
                return original;
            }

            if(thechar > 64 && thechar < 91){ //大写字母
                return original;
            }

            if(thechar > 96 && thechar < 123){ //小写字母
                return original;
            }        

            if(thechar>127) { //大于127用unicode
                var c = thechar;
                var a4 = c%16;
                c = Math.floor(c/16);
                var a3 = c%16;
                c = Math.floor(c/16);
                var a2 = c%16;
                c = Math.floor(c/16);
                var a1 = c%16;
                return "\\u"+hex[a1]+hex[a2]+hex[a3]+hex[a4]+"";        
            }
            else {
                return changeTo16Hex(original);
            }

        }
    }
function jsEncode(str){
    var hex=new Array('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f');
    var preescape = str;
    var escaped = "";
    var i=0;
    for(i=0; i < preescape.length; i++){
        escaped = escaped + encodeCharx(preescape.charAt(i));
    }
    return escaped;
}
```
- 例4：在js事件中输出

```html
/**
黑客可以提交$var=');alert(/xss/);//
那么实际上就变成了<a href=# onclick="funcA('');alert(/xss/);//')">test</a>
**/
<a href=# onclick="funcA('$var')">test</a>
```
<B>修复方式同例3，需要对变量进行JS编码</B>
- 例5：富文本的处理
某些允许用户提交自定义HTML代码的富文本功能，还是需要采用"输入检查"的方式，处理富文本时，JS事件应该被严格禁止(采用输入检查的方式过滤掉事件，代码参考上面的removexss函数)，富文本的展示需求里面不应该包括Js事件这种动态效果，同时一些危险的标签比如``<iframe>`` ``<script>`` ``<base>`` ``<form>``等也应该严格禁止，标签的选用上应采用白名单的方式进行控制，比如只允许``<a>`` ``<img>``等相对安全的标签存在。

- 例6：DOM型XSS的修复

```html
//变量先是输出在<script>标签中，然后又被输出到html页面中
//此时单纯的用HTML编码或者JS编码都无法达到很好的防御效果，因为浏览器会在渲染页面时解码
<script>
var x="$var";
document.write("<a href='"+x+"'>test</a>");
</script>
```
