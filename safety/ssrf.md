## SSRF漏洞【高危】
### 原理概述
SSRF(Server-Side Request Forgery，服务器端请求伪造)，该漏洞用一句话概括：在请求资源前，未检查是否为内网资源，造成泄露信息泄露，严重会造成内网机器被入侵。


当前有很多web应用,因为业务需要,都提供了从其他服务器获取数据的功能（比如使用用户提供的URL去加载图片，下载文件等等），如果程序对外界提供的URL检查不严格，就可能导致该功能被恶意利用，黑客可以利用该功能将服务器作为代理去攻击其他目标（比如本地或者远程的其他服务器）。这种攻击方式被称为服务端请求伪造（Server-side request forgery，简称SSRF）。

### 危害
1. 可以对服务器自身，服务器所在内网进行扫描探活的操作，获取一些服务的标识信息；
2. 可以将服务器作为攻击者的代理，对外网其他服务器发出恶意请求；
3. 对内网web应用进行指纹识别，进一步攻击内网的web应用；
4. 攻击运行在内网的其他应用（比如对某服务进行溢出攻击）；
5. 利用file协议读取文件，造成敏感信息泄露等；
...

### 造成原因
1. Web服务存在向外请求资源的功能(爬取网页、远程图片下载等)，通常使用了curl()、fopen()等函数。
2. 请求的url参数外界可控，即用户可通过传入参数的方式(如/fectch.do?url=http://abc.com/)来修改请求的url。
在请求资源前，没有判断该域名或IP是否为内网IP。即可通过该服务器做跳板访问内网资源，接近代理功能。
3. 可能修复不彻底，通过302、301等跳转绕过之前的内网判断，形成二次绕过。

### BadCase样例
BadCase样例1:
```php
/**
程序从用户指定的URL处获取文件内容并展示给用户，但是该URL并不可信，攻击者完全可以提交url=http://内网url 从而获取到内网信息

**/
$url=$_GET['url'];
if($url)
{
  $content=file_get_contents($url);
  $filename='./tmp/'.rand().'.read.txt';
  file_put_contents($filename,$content);
  header("Location:$filename");
}
```
BadCase样例2:
```php
/**
程序使用fsockopen函数从用户指定的URL处获取数据，同上例，传入的参数是从外界获取的且不经检查，同样存在安全隐患
**/
$host=$_GET['host'];
$port=$_GET['port']?intval($_GET['port']):80;
$link=$_GET['link'];
function GetFile($host,$port,$link)
{
  $fp = fsockopen($host, $port, $errno, $errstr, 30);
  if (!$fp)
  {
    echo "$errstr (error number $errno) \n";
  }
  else
  {
    $out = "GET $link HTTP/1.1\r\n";
    $out .= "Host: $host\r\n";
    $out .= "Connection: Close\r\n\r\n";
    $out .= "\r\n";
    fwrite($fp, $out);
    $contents='';
    while (!feof($fp))
    {
      $contents.= fgets($fp, 1024);
    }
    fclose($fp);
    return $contents;
  }
}
```
<B>请注意如下BadCase样例，是公司同学在编码时实际出现过的问题(已对真实代码简化处理)</B>

BadCase样例3:
```php
/**
本段代码主要有3大问题，分述如下：

1.url从外界获取，未经检查，不可信，如样例1,黑客可以提交url=http://内网 获取内网信息

2.curl跟随了跳转，这样即使url从外界获取之后进行了检查，还是可以被绕过。比如：
url从外界获取之后，进行检查，如果发现是内网地址就停止程序的执行，那么黑客可以采用如下绕过策略：
黑客首先提交一个正常的外网地址，比如为http://www.mydomain.com/index.php，但是这个index.php
中的代码为一个302跳转:<?php header("Location:http://内网");?> 那么之前的URL检查
就会被绕过，请求还是可以进入内网；

3.由于curl支持多种协议，从而可以造成多种不同的安全风险，本例中，黑客可以采用如下攻击方式：
a.提交url=file:///etc/passwd，从而可以读取到服务器上的敏感信息
b.提交url=gopher://redis_server_ip:6379/malicious_code 从而利用gopher协议去攻击内网redis服务器
(公司内网redis服务器就曾经遭受过此类攻击，导致黑客直接拿到服务器最高控制权)
···
**/
if(isset($_GET['url']))
{
  $url=$_GET['url'];
  $curl=curl_init();
  curl_setopt($curl,CURLOPT_URL,$url);
  curl_setopt($curl,CURLOPT_RETURNTRANSFER,1);
  curl_setopt($curl,CURLOPT_FOLLOWLOCATION,1);
  $result=curl_exec($curl);
  var_dump($result);
}
```
### 修复建议
1.首先需要针对实际的业务场景考虑以下几个问题：
- 业务是否需要与内网服务器通信？如果需要，要与哪些服务器通信？
- 业务是否需要跟随30x跳转？是否可以禁止跟随跳转？
- 业务是否需要支持除http,https协议以外的其他协议（如：ftp,file等等）？
- 业务所在服务器上是否还有其他业务？这些业务是否需要访问内网？

2.参考方案如下：
a.业务不需要与内网通信，且机器上没有其他业务需要访问内网，那么可直接配置iptables，禁止对内网进行请求，此方法最为简单粗暴，但是缺点在于以后如果要添加或者切换服务器，可能会忘记配置iptables的规则，导致漏洞再现，如果用此方案，需要注意机器变更时规则也应该做相应改动，样例如下：
```
iptables -t filter -A INPUT -s 192.168.0.0/16 -j DROP
iptables -t filter -A OUTPUT -s 192.168.0.0/16 -j DROP
iptables -t filter -A INPUT -s 10.0.0.0/8 -j DROP
iptables -t filter -A OUTPUT -s 10.0.0.0/8 -j DROP
iptables -t filter -A INPUT -s 172.16.0.0/12 -j DROP
iptables -t filter -A OUTPUT -s 172.16.0.0/12 -j DROP
```
b.业务需要与内网的某几台机器通信，且业务所在机器上无其他业务需要与内网通信，那么可以选用参考方案a（即配置iptables）或者在代码层面使用内网机器白名单进行处理

c.业务不需要与内网通信，但服务器上有其他业务，不能用iptables限制对内网请求，那么可以在代码层面使用白名单进行控制

修复该漏洞的核心思想为一句话:在任何请求资源之前，要通过IP来判断是否为内网环境，内网的资源一律不请求！
- 【强制】只允许HTTP协议和HTTPS协议:需使用parse_url()解析出sheme
- 【强制】每次请求资源前，判断是否为内网资源，并将IP与Host进行绑定后才能执行curl操作
- 【建议】关闭跳转(30x)跟随，因为curl()请求封装了中间环节，如果开启跟随，中间环节跳转到内网IP，仍会请求内网资源。curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);  //关闭跟随
- 如果有302跳转等用户体验上的需求，则需要手动实现302跟随，即每次获取Location: (.\*)，然后每次请求资源前，都需要通过IP判断是否是内网，内网IP一律不执行curl操作。curl_setopt($ch, CURLOPT_HEADER, true);  //输出Header头，根据 Header 获取 Location

```php
<?php
/**
 * Class SafeCurl
 * @author  xulichen @ SMD
 * 2016-08-16 15:09
 */
class SafeCurl
{
    public $ch;
    public $url = '';

    public $whitelist = array(
        "ip" => array(),
        "scheme" => array('http', 'https',),
        "port" => array('all',),
        "content_type" => array('all',),
        "ip:port" => array(),
    );

    public $ssrf_config = array(
        "allow_redirect" => false,
        "redirect_count" => 3, //页面访问深度
        "crawl_timeout" => 2,
        "user-agent" => "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36",
    );
    // output
    public $output = array(
        "isValid" => false,
        "info" => '',
    );

    /**
     * SafeCurl constructor.
     * @param null $whitelist
     * @param null $ssrf_config
     */
    function __construct($whitelist=null, $ssrf_config=null)
    {
        if (!is_null($whitelist)){
            $this->whitelist = $whitelist;
        }
        if (!is_null($ssrf_config)){
            $this->ssrf_config = $ssrf_config;
        }
        $this->ch = curl_init();
    }
    function __destruct()
    {
        curl_close($this->ch);
    }

    /**
     * 单次添加指定类型的白名单信息
     * @param $type
     * @param $value
     */
    public function addWhitelist($type, $value){
        if (in_array('all', $this->whitelist[$type])){
            $this->whitelist[$type] = array();
        }
        array_push($this->whitelist[$type], $value);
    }

    /**
     * 设置是否允许重定向
     */
    public function allowRedirect(){
        $this->ssrf_config["allow_redirect"] = true;
    }

    /**
     * 设置页面访问深度
     * @param $count
     */
    public function setRedirectCount($count){
        $this->ssrf_config["redirect_count"] = $count;
    }

    /**
     * 设置curl爬取的超时时间
     * @param $time
     */
    public function setCrawlTimeout($time){
        $this->ssrf_config["crawl_timeout"] = $time;
    }

    /**
     * 设置curl的User-Agent
     * @param $ua
     */
    public function setUA($ua){
        $this->ssrf_config["user-agent"] = $ua;
    }

    /**
     * @param $ch
     */
    public function setCurlHandle($ch){
        $this->ch = $ch;
    }

    /**
     * @param $url
     * @return array
     */
    public function checkURL($url){
        $param = array(
            "url" => '',
            "isValid" => true,
            "parts" => array(),
            "info" => '',
        );
        // 分析url
        if ($url) {
            $parts = parse_url($url);
        } else {
            $param['isValid']=false;
            $param['info']='This URL is Empty.';
            $this->output['info'] = $param['info'];
            return $param;
        }

        //没有scheme 添加 http://
        if (!isset($parts['scheme'])) {
            $url = 'http://'.$url;
            $scheme = 'http';
        } else{
            $scheme = $parts['scheme'];
        }
        // 若没有host 添加scheme 重新判断
        if (!isset($parts['host'])) {
            $parts = parse_url($url);
        }
        // parse_url 若url 为非法 则返回 bool false
        if (!$parts){
            $parts = array();
        }
        // 判断白名单协议
        if(!in_array($scheme, $this->whitelist['scheme'])){
            $param['isValid'] = false;
            $param['info'] .= '[scheme]';
        }

        // 判断白名单端口
        if(array_key_exists('port', $parts)){
            $port = $parts['port'];
            if(!in_array($port, $this->whitelist['port']) && !in_array('all', $this->whitelist['port'])){
                $param['isValid'] = false;
                $param['info'] .= '[port]';
            }
        } else{
            // 补全默认端口
            if ($scheme === 'http'){
                $parts['port'] = 80;
            }
            if ($scheme === 'https'){
                $parts['port'] = 443;
            }
        }

        // 判断 ip:port 形式白名单
        $ip_port = @$parts['host'].":".@$parts['port'];
        if (in_array($ip_port, $this->whitelist['ip:port'])){
            $param['isValid'] = true;
        }
        // 整体判断url是否合法
        $param['url'] = $url;
        $res = filter_var($url, FILTER_VALIDATE_URL);
        // 新增host为空判断
        if ($res && $param['isValid']){
            $param['parts'] = $parts;
        } else{
            $param['isValid'] = false;
            $this->output['info'] = $param['info'].'This URL is invalid.';
        }
        return $param;
    }

    /**
     * 判断IP是否为外网IP
     * @param $ip
     * @return bool true -> 外网IP false -> 内网
     */
    public function checkIP($ip){
        $isValidIP = true;
        if(in_array($ip, $this->whitelist["ip"])){
            return true;
        }
        // 单独判断 loopback 127.x.x.x
        $sp = explode('.', $ip);
        if ($sp[0] === '127'){
            $isValidIP = false;
        }
        //整体判断是否为外网IP
        $res = filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE |  FILTER_FLAG_NO_RES_RANGE);
        if($res && $isValidIP){
            return true;
        } else{
            $this->output['info'] = 'IP invalid.';
            return false;
        }
    }

    /**
     * 通过URL验证对应IP是否合法
     * @param $url
     * @return bool
     */
    public function validate($url)
    {
        $res = $this->checkURL($url);
        if($res['isValid'] === false){
            return false;
        } else{
            $ip = @gethostbyname($res['parts']['host']);
            $ip_port = $ip.":".@$res['parts']['port'];
            if (in_array($ip_port, $this->whitelist['ip:port'])){
                return true;
            }
            if ($this->checkIP($ip)){
                return true;
            } else{
                return false;
            }
        }

    }

    /**
     * curl安全参数单次访问
     * @param $url
     * @return array
     */
    public function fetch_one($url){
        $ch = $this->ch;
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, true); // 头文件的信息作为数据流输出
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // 以字符串返回,而非直接输出
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // 关闭重定向
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->ssrf_config["crawl_timeout"]);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->ssrf_config["user-agent"]);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0); // 需CURL配置文件,否则出现HTTPS错误
        $response = curl_exec($ch);
        if ($response){
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $http_content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $http_header = substr($response, 0, $header_size);
            $http_body = substr($response, $header_size);
            $res = array(
                "isValid" => true,
                "response" => $response,
                "http_code" => $http_code,
                "http_content_type" => $http_content_type,
                "http_header" => $http_header,
                "http_body" => $http_body,
                "curl_handle" => $ch,
            );
            return $res;
        } else{
            $res = array(
                "isValid" => false,
                "curl_error" => curl_error($ch),
            );
            return $res;
        }

    }

    /**
     * 核心逻辑为手动获取location,并逐次验证url是否合法
     * 只有HTTP状态为200,且在规定次数内,才返回完整output
     * @param $url
     * @return array
     */
    public function execute($url){
        $res = null;
        $url_valid = true;
        $this->output["url_route"] = array();
        $url = trim($url);


        if (!$this->ssrf_config['allow_redirect']){
            $this->ssrf_config['redirect_count'] = 1;
        }
        for ($i = 1;$i <= $this->ssrf_config['redirect_count']; $i++){
            array_push($this->output['url_route'], $url);
            if (!$this->validate($url)){
                //每次均验证 url合法性
                $url_valid = false;
                break;
            }
            $res = $this->fetch_one($url);
            if ($res['isValid'] === false){
                $this->output['info'] = $res['curl_error'];
                break;
            }
            if ($res['http_code'] === 200){

                if(!in_array($res['http_content_type'], $this->whitelist['content_type'])
                    && !in_array('all', $this->whitelist['content_type'])){
                    $this->output['info'] = 'This content_type is not allowed';
                    break;
                } else{
                    $this->output['isValid'] = true;
                    break;
                }
            }
            if ($res['http_code'] !== 200 && $i === $this->ssrf_config['redirect_count']){
                $this->output['info'] = '已达到循环次数限制,非200弃包';
                break;

            }else {
                preg_match_all('/^Location:(.*)$/mi', $res["response"], $matches);
                if (!empty($matches[1])){
                    $url = trim($matches[1][0]);
                } else{
                    $this->output['info'] = 'Can not find location.';
                    break;
                }
            }
        }

        if ($url_valid){
            if ($this->output['isValid']){
                $this->output['response'] = $res['response'];
                $this->output['http_code'] = $res['http_code'];
                $this->output['http_content_type'] = $res['http_content_type'];
                $this->output['http_header'] = $res['http_header'];
                $this->output['http_body'] = $res['http_body'];
                $this->output['destination_url'] = end($this->output['url_route']);
            }
            return $this->output;
        } else{
            return $this->output;
        }
    }

}
```
