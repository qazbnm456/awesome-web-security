# Awesome Web Security [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

[<img src="https://upload.wikimedia.org/wikipedia/commons/6/61/HTML5_logo_and_wordmark.svg" align="right" width="70">](https://www.w3.org/TR/html5/)

> 🐶 Curated list of Web Security materials and resources.

Needless to say, most of websites on-line are suffered from various type of bugs, which might eventually lead to vulnerabilities. Why would this happen so often? Many factors can be involved, including misconfiguration, shortage of engineers' security skills, and etc. Therefore, here is the curated list of Web Security materials and resources for learning the cutting edge penetrating techniques.

*Please read the [contribution guidelines](CONTRIBUTING.md) before contributing.*

---

<p align="center"><b>🌈 Want to strengthen your penetration skills?</b><br>I would recommend to play some <a href="https://github.com/apsdehal/awesome-ctf" target="_blank">awesome-ctf</a>s.</p>

---

Check out my [repos](https://github.com/qazbnm456) 🐾 or say *hi* on my [Twitter](https://twitter.com/qazbnm456).

## Contents

- [Forums](#forums)
- [Resources](#resources)
    - [Introductions](#introductions)
        - [XSS](#introductions-xss)
        - [SQL Injection](#introductions-sql-injection)
        - [XML](#introductions-xml)
        - [XXE](introductions-xxe)
        - [CSRF](#introductions-csrf)
        - [SSRF](#introductions-ssrf)
        - [Rails](#introductions-rails)
        - [AngularJS](#introductions-angularjs)
        - [SSL/TLS](#introductions-ssl-tls)
        - [Webmail](#introductions-webmail)
        - [AWS](#introductions-aws)
        - [Fingerprint](#introductions-fingerprint)
    - [Books](#books)
- [Evasions](#evasions)
    - [CSP](#evasions-csp)
    - [WAF](#evasions-waf)
    - [JSMVC](#evasions-jsmvc)
    - [Authentication](#evasions-authentication)
- [Tricks](#tricks)
    - [Remote Code Execution](#tricks-rce)
    - [XSS](#tricks-xss)
    - [SQL Injection](#tricks-sql-injection)
    - [NoSQL Injection](#tricks-nosql-injection)
    - [SSRF](#tricks-ssrf)
    - [Header Injection](#tricks-header-injection)
    - [URL](#tricks-url)
    - [Others](#tricks-others)
- [Browser Exploitation](#browser-exploitation)
- [PoCs](#pocs)
    - [JavaScript](#pocs-javascript)
- [Tools](#tools)
    - [Reconnaissance](#tools-reconnaissance)
    - [Code Generating](#tools-code-generating)
    - [Fuzzing](#tools-fuzzing)
    - [Penetrating](#tools-penetrating)
    - [Leaking](#tools-leaking)
    - [Detecting](#tools-detecting)
    - [Preventing](#tools-preventing)
    - [Webshell](#tools-webshell)
    - [Disassembler](#tools-disassembler)
    - [Others](#tools-others)
- [Social Engineering Database](#social-engineering-database)
- [Blogs](#blogs)
- [Twitter Users](#twitter-users)
- [Practices](#practices)
    - [AWS](#practices-aws)
    - [XSS](#practices-xss)
- [Community](#community)
- [Miscellaneous](#miscellaneous)

## Forums

* [Drops (backup)](https://drops.secquan.org/) - Drops was known as a famous knowledge base for hacking technology.
* [Paper from Seebug](http://paper.seebug.org/) - Knowledge base for hacking technology built by [Seebug](http://seebug.org/).
* [Freebuf](http://www.freebuf.com/) - Freebuf is the most popular forum in China for exchanging and sharing hacking technology.
* [安全脉搏](https://www.secpulse.com/) - Blog for Security things.
* [HackDig](http://en.hackdig.com/) - Dig high-quality web security articles for hacker.
* [T00LS](https://www.t00ls.net/) - T00LS - 低调求发展 - 潜心习安全.

## Resources

### Introductions

<a name="introductions-xss"></a>
### XSS

* [H5SC](https://github.com/cure53/H5SC) - HTML5 Security Cheatsheet - Collection of HTML5 related XSS attack vectors by [@cure53](https://github.com/cure53).
* [XSS.png](https://github.com/jackmasa/XSS.png) - XSS mind map by [@jackmasa](https://github.com/jackmasa).
* [C.XSS Guide](https://excess-xss.com/) - Comprehensive tutorial on cross-site scripting by [@JakobKallin](https://github.com/JakobKallin) and [Irene Lobo Valbuena](https://www.linkedin.com/in/irenelobovalbuena/).

<a name="introductions-sql-injection"></a>
### SQL Injection

* [HQL for pentesters](http://blog.h3xstream.com/2014/02/hql-for-pentesters.html) - Written by [@h3xstream](https://twitter.com/h3xstream/).

<a name="introductions-xml"></a>
### XML

* [XML实体攻击 - 从内网探测到命令执行步步惊心](http://www.freebuf.com/video/49961.html) - Written by 张天琪.

<a name="introductions-xxe"></a>
### XXE

* [XXE](https://phonexicum.github.io/infosec/xxe.html) - Written by [@phonexicum](https://twitter.com/phonexicum).

<a name="introductions-csrf"></a>
### CSRF

* [讓我們來談談 CSRF](http://blog.techbridge.cc/2017/02/25/csrf-introduction/) - Written by [TechBridge](http://blog.techbridge.cc/).

<a name="introductions-ssrf"></a>
### SSRF

* [SSRF bible. Cheatsheet](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit) - Written by [@Wallarm](https://twitter.com/wallarm).

<a name="introductions-rails"></a>
### Rails

* [Rails 動態樣板路徑的風險](http://devco.re/blog/2015/07/24/the-vulnerability-of-dynamic-render-paths-in-rails/) - Written by [Shaolin](http://devco.re/blog/author/shaolin/).
* [Rails Security - First part](https://hackmd.io/s/SkuTVw5O-) - Written by [@qazbnm456](https://github.com/qazbnm456).

<a name="introductions-angularjs"></a>
### AngularJS

* [XSS without HTML: Client-Side Template Injection with AngularJS](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html) - Written by [Gareth Heyes](https://www.blogger.com/profile/10856178524811553475).
* [DOM based Angular sandbox escapes](http://blog.portswigger.net/2017/05/dom-based-angularjs-sandbox-escapes.html) - Written by [@garethheyes](https://twitter.com/garethheyes)

<a name="introductions-ssl-tls"></a>
### SSL/TLS

* [SSL & TLS Penetration Testing](https://www.aptive.co.uk/blog/tls-ssl-security-testing/) - Written by [APTIVE](https://www.aptive.co.uk/).

<a name="introductions-webmail"></a>
### Webmail

* [Webmail-Hacking](https://github.com/mottoin/SecPaper/blob/master/Webmail-Hacking.pdf) - Written by [千域千寻](http://blog.csdn.net/f1n4lly/).

<a name="introductions-aws"></a>
### AWS

* [PENETRATION TESTING AWS STORAGE: KICKING THE S3 BUCKET](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/) - Written by Dwight Hohnstein from [Rhino Security Labs](https://rhinosecuritylabs.com/).

<a name="introductions-fingerprint"></a>
### Fingerprint

* [浅谈Web客户端追踪](http://www.freebuf.com/articles/web/127266.html) - Written by [arkteam](http://www.freebuf.com/author/arkteam).

### Books

* [Security Geek 2016 - Part. A](http://bobao.360.cn/download/book/security-geek-2016-A.pdf) - Written by [360网络攻防实验室](http://bobao.360.cn/).
* [Security Geek 2016 - Part. B](http://bobao.360.cn/download/book/security-geek-2016-B.pdf) - Written by [360网络攻防实验室](http://bobao.360.cn/).
* [Security Geek 2017 - Q1](http://bobao.360.cn/download/book/security-geek-2017-q1.pdf) - Written by [360网络攻防实验室](http://bobao.360.cn/).
* [Security Geek 2017 - Q2](http://bobao.360.cn/download/book/security-geek-2017-q2.pdf) - Written by [360网络攻防实验室](http://bobao.360.cn/).

## Evasions

<a name="evasions-csp"></a>
### CSP

* [CSP: bypassing form-action with reflected XSS](https://labs.detectify.com/2016/04/04/csp-bypassing-form-action-with-reflected-xss/) - Written by [Detectify Labs](https://labs.detectify.com/).
* [TWITTER XSS + CSP BYPASS](http://www.paulosyibelo.com/2017/05/twitter-xss-csp-bypass.html) - Written by [Paulos Yibelo](http://www.paulosyibelo.com/).

<a name="evasions-waf"></a>
### WAF

* [浅谈json参数解析对waf绕过的影响](https://xianzhi.aliyun.com/forum/read/553.html) - Written by [doggy](https://xianzhi.aliyun.com/forum/u.php?uid=1723895737531437).
* [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/) - Written by [@Brett Buerhaus](https://twitter.com/bbuerhaus).
* [How to bypass libinjection in many WAF/NGWAF](https://medium.com/@d0znpp/how-to-bypass-libinjection-in-many-waf-ngwaf-1e2513453c0f)

<a name="evasions-jsmvc"></a>
### JSMVC

* [JavaScript MVC and Templating Frameworks](http://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).

<a name="evasions-authentication"></a>
### Authentication

* [Trend Micro Threat Discovery Appliance - Session Generation Authentication Bypass (CVE-2016-8584)](http://blog.malerisch.net/2017/04/trend-micro-threat-discovery-appliance-session-generation-authentication-bypass-cve-2016-8584.html) - Written by [@malerisch](https://twitter.com/malerisch) and [@steventseeley](https://twitter.com/steventseeley).
* [Yahoo Bug Bounty: Chaining 3 Minor Issues To Takeover Flickr Accounts](http://blog.mish.re/index.php/2017/04/29/yahoo-bug-bounty-chaining-3-minor-issues-to-takeover-flickr-accounts/) - Written by [Mishre](http://blog.mish.re/).

## Tricks

<a name="tricks-rce"></a>
### Remote Code Execution

* [Exploiting Node.js deserialization bug for Remote Code Execution](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) - Written by [OpSecX](https://opsecx.com/index.php/author/ajinabraham/).
* [eval长度限制绕过 && PHP5.6新特性](https://www.leavesongs.com/PHP/bypass-eval-length-restrict.html) - Written by [PHITHON](https://www.leavesongs.com/).
* [PHP垃圾回收机制UAF漏洞分析](http://www.freebuf.com/vuls/122938.html) - Written by [ph1re](http://www.freebuf.com/author/ph1re).
* [DRUPAL 7.X SERVICES MODULE UNSERIALIZE() TO RCE](https://www.ambionics.io/blog/drupal-services-module-rce) - Written by [Ambionics Security](https://www.ambionics.io/).
* [How we exploited a remote code execution vulnerability in math.js](https://capacitorset.github.io/mathjs/) - Written by [@capacitorset](https://github.com/capacitorset).
* [GitHub Enterprise Remote Code Execution](http://exablue.de/blog/2017-03-15-github-enterprise-remote-code-execution.html) - Written by [@iblue](https://github.com/iblue).
* [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) - Written by [Orange](http://blog.orange.tw/).
* [How i Hacked into a PayPal's Server - Unrestricted File Upload to Remote Code Execution](http://blog.pentestbegins.com/2017/07/21/hacking-into-paypal-server-remote-code-execution-2017/) - Written by [Vikas Anil Sharma](http://blog.pentestbegins.com/).

<a name="tricks-xss"></a>
### XSS

* [ECMAScript 6 from an Attacker's Perspective - Breaking Frameworks, Sandboxes, and everything else](http://www.slideshare.net/x00mario/es6-en) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).
* [How I found a $5,000 Google Maps XSS (by fiddling with Protobuf)
](https://medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff#.u50nrzhas) - Written by [Marin Moulinier](https://medium.com/@marin_m).
* [DON'T TRUST THE DOM: BYPASSING XSS MITIGATIONS VIA SCRIPT GADGETS](https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf) - Written by [Sebastian Lekies](https://twitter.com/slekies), [Krzysztof Kotowicz](https://twitter.com/kkotowicz), and [Eduardo Vela](https://twitter.com/sirdarckcat).
* [Uber XSS via Cookie](http://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie/) - Written by [zhchbin](http://zhchbin.github.io/).

<a name="tricks-sql-injection"></a>
### SQL Injection

* [屌智硬之mysql不用逗号注入](http://www.jinglingshu.org/?p=2220) - Written by [jinglingshu](http://www.jinglingshu.org/?p=2220).
* [见招拆招：绕过WAF继续SQL注入常用方法](http://www.freebuf.com/articles/web/36683.html) - Written by [mikey](http://www.freebuf.com/author/mikey).
* [MySQL Error Based SQL  Injection Using  EXP](https://www.exploit-db.com/docs/37953.pdf) - Written by [@osandamalith](https://twitter.com/osandamalith).
* [SQL injection in an UPDATE query - a bug bounty story!](http://zombiehelp54.blogspot.jp/2017/02/sql-injection-in-update-query-bug.html) - Written by [Zombiehelp54](http://zombiehelp54.blogspot.jp/).
* [GitHub Enterprise SQL Injection](http://blog.orange.tw/2017/01/bug-bounty-github-enterprise-sql-injection.html) - Written by [Orange](http://blog.orange.tw/).

<a name="tricks-nosql-injection"></a>
### NoSQL Injection

* [GraphQL NoSQL Injection Through JSON Types](https://medium.com/@east5th/graphql-nosql-injection-through-json-types-a1a0a310c759) - Written by [@east5th](https://medium.com/@east5th).

<a name="tricks-ssrf"></a>
### SSRF

* [SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748) - Written by [aesteral](https://hackerone.com/aesteral).
* [SSRF漏洞中绕过IP限制的几种方法总结](http://www.freebuf.com/articles/web/135342.html) - Written by [arkteam](http://www.freebuf.com/author/arkteam).
* [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) - Written by [Orange](http://blog.orange.tw/).
* [SSRF Tips](http://blog.safebuff.com/2016/07/03/SSRF-Tips/) - Written by [xl7dev](http://blog.safebuff.com/).

<a name="tricks-header-injection"></a>
### Header Injection

* [Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by [Timothy Morgan](https://plus.google.com/105917618099766831589).

<a name="tricks-url"></a>
### URL

* [URL Hacking - 前端猥琐流](http://php.ph/wydrops/drops/URL%20Hacking%20-%20前端猥琐流.pdf) - Written by [0x_Jin](http://xssec.lofter.com/).
* [Phishing with Unicode Domains](https://www.xudongz.com/blog/2017/idn-phishing/) - Written by [Xudong Zheng](https://www.xudongz.com/).
* [Unicode Domains are bad and you should feel bad for supporting them](https://www.vgrsec.com/post20170219.html) - Written by [VRGSEC](https://www.vgrsec.com/).

<a name="tricks-others"></a>
### Others

* [Some Tricks From My Secret Group](https://www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html) - Written by [PHITHON](https://www.leavesongs.com/).
* [CTF比赛总是输？你还差点Tricks!](https://docs.google.com/presentation/d/1Cx0vI2Mzy0zwdTrgic3S3TwGMCpH-QhMUdHU1r3AYfI/edit#slide=id.g35f391192_065) - Written by [PHITHON](https://www.leavesongs.com/).
* [隱匿的攻擊之-Domain Fronting](https://evi1cg.me/archives/Domain_Fronting.html) - Written by [Evi1cg](https://evi1cg.me/).
* [Uber Bug Bounty: Gaining Access To An Internal Chat System](http://blog.mish.re/index.php/2017/09/06/uber-bug-bounty-gaining-access-to-an-internal-chat-system/) - Written by [MISHRE](http://blog.mish.re/).

## Browser Exploitation

### Frontend (like CSP bypass, URL spoofing, and something like that)

* [JSON hijacking for the modern web](http://blog.portswigger.net/2016/11/json-hijacking-for-modern-web.html) - Written by [portswigger](https://portswigger.net/).
* [IE11 Information disclosure - local file detection](https://www.facebook.com/ExploitWareLabs/photos/a.361854183878462.84544.338832389513975/1378579648872572/?type=3&theater) - Written by James Lee.
* [SOP bypass / UXSS – Stealing Credentials Pretty Fast (Edge)](https://www.brokenbrowser.com/sop-bypass-uxss-stealing-credentials-pretty-fast/) - Written by [Manuel](https://twitter.com/magicmac2000).
* [ブラウザの脆弱性とそのインパクト](https://speakerdeck.com/nishimunea/burauzafalsecui-ruo-xing-tosofalseinpakuto) - Written by [Muneaki Nishimura](https://speakerdeck.com/nishimunea) and [Masato Kinugawa](https://twitter.com/kinugawamasato).

### Backend (core of Browser implementation, and often refers to C or C++ part)

* [First Step to Browser Exploitation](http://mashirogod.dothome.co.kr/index.php/2017/01/07/first-step-to-browser-exploitation/) - Written by [Brian Pak](http://mashirogod.dothome.co.kr/).
* [Attacking JavaScript Engines - A case study of JavaScriptCore and CVE-2016-4622](http://www.phrack.org/papers/attacking_javascript_engines.html) - Written by [phrack@saelo.net](phrack@saelo.net).
* [Three roads lead to Rome](http://blogs.360.cn/360safe/2016/11/29/three-roads-lead-to-rome-2/) - Written by [Luke Viruswalker](http://blogs.360.cn/360safe/author/xsecure/).
* [Exploiting a V8 OOB write.](https://halbecaf.com/2017/05/24/exploiting-a-v8-oob-write/) - Written by [@halbecaf](https://twitter.com/halbecaf).
* [FROM CRASH TO EXPLOIT: CVE-2015-6086 – OUT OF BOUND READ/ASLR BYPASS](http://payatu.com/from-crash-to-exploit/) - Written by [payatu](http://payatu.com/).

## PoCs

<a name="pocs-javascript"></a>
### JavaScript

* [js-vuln-db](https://github.com/tunz/js-vuln-db) - Collection of JavaScript engine CVEs with PoCs by [@tunz](https://github.com/tunz).
* [awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc) - Curated list of CVE PoCs by [@qazbnm456](https://github.com/qazbnm456).
* [Some-PoC-oR-ExP](https://github.com/coffeehb/Some-PoC-oR-ExP) - 各种漏洞poc、Exp的收集或编写 by [@coffeehb](https://github.com/coffeehb).

## Tools

<a name="tools-reconnaissance"></a>
### Reconnaissance

* [xray](https://github.com/evilsocket/xray) - XRay is a tool for recon, mapping and OSINT gathering from public networks by [@evilsocket](https://github.com/evilsocket).
* [Shodan](https://www.shodan.io/) - Shodan is the world's first search engine for Internet-connected devices by [@shodanhq](https://twitter.com/shodanhq).
* [Censys](https://censys.io/) - Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet by [University of Michigan](https://umich.edu/).
* [urlscan.io](https://urlscan.io/) - Service which analyses websites and the resources they request by [@heipei](https://twitter.com/heipei).
* [ZoomEye](https://www.zoomeye.org/) - ZoomEye 是一个针对网络空间的搜索引擎 by [@zoomeye_team](https://twitter.com/zoomeye_team).
* [FOFA](https://fofa.so/) - 网络空间资产搜索引擎 by [白帽汇](http://baimaohui.net/).
* [NSFOCUS](https://nti.nsfocus.com/) - THREAT INTELLIGENCE PORTAL by NSFOCUS GLOBAL.
* [傻蛋联网设备搜索](https://www.oshadan.com/) - 监测互联网基础设施安全威胁 by [@傻蛋搜索](http://weibo.com/shadansou).
* [gitrob](https://github.com/michenriksen/Gitrob) - Reconnaissance tool for GitHub organizations by [@michenriksen](https://github.com/michenriksen).
* [raven](https://github.com/0x09AL/raven) - raven is a Linkedin information gathering tool that can be used by pentesters to gather information about an organization employees using Linkedin by [@0x09AL](https://github.com/0x09AL).
* [ReconDog](https://github.com/UltimateHackers/ReconDog) - Recon Dog is an all in one tool for all your basic information gathering needs by [@UltimateHackers](https://github.com/UltimateHackers).
* [AQUATONE](https://github.com/michenriksen/aquatone) - Tool for Domain Flyovers by [@michenriksen](https://github.com/michenriksen).
* [domain_analyzer](https://github.com/eldraco/domain_analyzer) - Analyze the security of any domain by finding all the information possible by [@eldraco](https://github.com/eldraco).
* [VirusTotal domain information](https://www.virustotal.com/en/documentation/searching/#getting-domain-information) - Searching for domain information by [VirusTotal](https://www.virustotal.com/).
* [Certificate Transparency](https://github.com/google/certificate-transparency) - Google's Certificate Transparency project fixes several structural flaws in the SSL certificate system by [@google](https://github.com/google).
* [Certificate Search](https://crt.sh/) - Enter an Identity (Domain Name, Organization Name, etc), a Certificate Fingerprint (SHA-1 or SHA-256) or a crt.sh ID to search certificate(s) by [@crtsh](https://github.com/crtsh).

<a name="tools-code-generating"></a>
### Code Generating

* [VWGen](https://github.com/qazbnm456/VWGen) - Vulnerable Web applications Generator by [@qazbnm456](https://github.com/qazbnm456).

<a name="tools-fuzzing"></a>
### Fuzzing

* [wfuzz](https://github.com/xmendez/wfuzz) - Web application bruteforcer by [@xmendez](https://github.com/xmendez).
* [charsetinspect](https://github.com/hack-all-the-things/charsetinspect) - Script that inspects multi-byte character sets looking for characters with specific user-defined properties by [@hack-all-the-things](https://github.com/hack-all-the-things).
* [IPObfuscator](https://github.com/OsandaMalith/IPObfuscator) - Simple too to convert the IP to a DWORD IP by [@OsandaMalith](https://github.com/OsandaMalith).
* [wpscan](https://github.com/wpscanteam/wpscan) - WPScan is a black box WordPress vulnerability scanner by [@wpscanteam](https://github.com/wpscanteam).
* [JoomlaScan](https://github.com/drego85/JoomlaScan) - Free software to find the components installed in Joomla CMS, built out of the ashes of Joomscan by [@drego85](https://github.com/drego85).
* [XSStrike](https://github.com/UltimateHackers/XSStrike) - XSStrike is a program which can fuzz and bruteforce parameters for XSS. It can also detect and bypass WAFs by [@UltimateHackers](https://github.com/UltimateHackers).
* [xssor2](https://github.com/evilcos/xssor2) - XSS'OR - Hack with JavaScript by [@evilcos](https://github.com/evilcos).

<a name="tools-penetrating"></a>
### Penetrating

* [Burp Suite](https://portswigger.net/burp/) - Burp Suite is an integrated platform for performing security testing of web applications by [portswigger](https://portswigger.net/).
* [mitmproxy](https://github.com/mitmproxy/mitmproxy) - Interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers by [@mitmproxy](https://github.com/mitmproxy).

<a name="tools-leaking"></a>
### Leaking

* [HTTPLeaks](https://github.com/cure53/HTTPLeaks) - All possible ways, a website can leak HTTP requests by [@cure53](https://github.com/cure53).
* [dvcs-ripper](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN/GIT/HG... by [@kost](https://github.com/kost).
* [DVCS-Pillage](https://github.com/evilpacket/DVCS-Pillage) - Pillage web accessible GIT, HG and BZR repositories by [@evilpacket](https://github.com/evilpacket).
* [GitMiner](https://github.com/UnkL4b/GitMiner) - Tool for advanced mining for content on Github by [@UnkL4b](https://github.com/UnkL4b).

<a name="tools-detecting"></a>
### Detecting

* [sqlchop](https://github.com/chaitin/sqlchop) - [DEPRECATED] Novel SQL injection detection engine built on top of SQL tokenizing and syntax analysis by [chaitin](http://chaitin.com).
* [retire.js](https://github.com/RetireJS/retire.js) - Scanner detecting the use of JavaScript libraries with known vulnerabilities by [@RetireJS](https://github.com/RetireJS).
* [malware-jail](https://github.com/HynekPetrak/malware-jail) - Sandbox for semi-automatic Javascript malware analysis, deobfuscation and payload extraction by [@HynekPetrak](https://github.com/HynekPetrak).
* [repo-supervisor](https://github.com/auth0/repo-supervisor) - Scan your code for security misconfiguration, search for passwords and secrets.

<a name="tools-preventing"></a>
### Preventing

* [js-xss](https://github.com/leizongmin/js-xss) - Sanitize untrusted HTML (to prevent XSS) with a configuration specified by a Whitelist by [@leizongmin](https://github.com/leizongmin).

<a name="tools-webshell"></a>
### Webshell

* [webshell](https://github.com/tennc/webshell) - This is a webshell open source project by [@tennc](https://github.com/tennc).
* [Weevely](https://github.com/epinna/weevely3) - Weaponized web shell by [@epinna](https://github.com/epinna).
* [Webshell-Sniper](https://github.com/WangYihang/Webshell-Sniper) - Manage your website via terminal by [@WangYihang](https://github.com/WangYihang).

<a name="tools-disassembler"></a>
### Disassembler

* [plasma](https://github.com/plasma-disassembler/plasma) - Plasma is an interactive disassembler for x86/ARM/MIPS by [@plasma-disassembler](https://github.com/plasma-disassembler).
* [radare2](https://github.com/radare/radare2) - Unix-like reverse engineering framework and commandline tools by [@radare](https://github.com/radare).
* [Iaitō](https://github.com/hteso/iaito) - Qt and C++ GUI for radare2 reverse engineering framework by [@hteso](https://github.com/hteso).

<a name="tools-others"></a>
### Others

* [Dnslogger](https://wiki.skullsecurity.org/index.php?title=Dnslogger) - DNS Logger by [@iagox86](https://github.com/iagox86).
* [CyberChef](https://github.com/gchq/CyberChef) - The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis - by [@GCHQ](https://github.com/gchq).

## Social Engineering Database

**use at your own risk**

* [haveibeenpwned](https://haveibeenpwned.com/) - Check if you have an account that has been compromised in a data breach by [Troy Hunt](https://www.troyhunt.com/).
* [70 SECURITY TEAM Social Engineering Data](http://s.70sec.com/) - 70 SECURITY TEAM 社工库 by [70 Security Team](http://70sec.com/).
* [mysql-password](http://www.mysql-password.com/database/1) - Database of MySQL hashes.

## Blogs

* [Orange](http://blog.orange.tw/) - Taiwan's talented web penetrator.
* [leavesongs](https://www.leavesongs.com/) - China's talented web penetrator.
* [Broken Browser](https://www.brokenbrowser.com/) - Fun with Browser Vulnerabilities.
* [Blog of Osanda](https://osandamalith.com/) - Security Researching and Reverse Engineering.
* [BRETT BUERHAUS](https://buer.haus/) - Vulnerability disclosures and rambles on application security.
* [n0tr00t](https://www.n0tr00t.com/) - ~# n0tr00t Security Team.

## Twitter Users

* [@filedescriptor](https://twitter.com/filedescriptor) - Active penetrator often tweets and writes useful articles
* [@cure53berlin](https://twitter.com/cure53berlin) - [Cure53](https://cure53.de/) is a German cybersecurity firm.
* [@XssPayloads](https://twitter.com/XssPayloads) - The wonderland of JavaScript unexpected usages, and more.
* [@kinugawamasato](https://twitter.com/kinugawamasato) - Japanese web penetrator.
* [@h3xstream](https://twitter.com/h3xstream/) - Security Researcher, interested in web security, crypto, pentest, static analysis but most of all, samy is my hero.
* [@garethheyes](https://twitter.com/garethheyes) - English web penetrator.

## Practices

<a name="practices-aws"></a>
### AWS

* [FLAWS](http://flaws.cloud/) - Amazon AWS CTF challenge - Written by [@0xdabbad00](https://twitter.com/0xdabbad00).

<a name="practices-xss"></a>
### XSS

* [alert(1) to win](https://alf.nu/alert1) - Series of XSS challenges - Written by [@steike](https://twitter.com/steike).
* [prompt(1) to win](http://prompt.ml/) - Complex 16-Level XSS Challenge held in summer 2014 (+4 Hidden Levels) - Written by [@cure53](https://github.com/cure53).

## Community

* [Reddit](https://www.reddit.com/r/websecurity/)
* [Stack Overflow](http://stackoverflow.com/questions/tagged/security)

## Miscellaneous

* [awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty) - Comprehensive curated list of available Bug Bounty & Disclosure Programs and write-ups by [@djadmin](https://github.com/djadmin).
* [bug-bounty-reference](https://github.com/ngalongc/bug-bounty-reference) - List of bug bounty write-up that is categorized by the bug nature by [@ngalongc](https://github.com/ngalongc).
* [Google VRP and Unicorns](https://sites.google.com/site/bughunteruniversity/behind-the-scenes/presentations/google-vrp-and-unicorns) - Written by [Daniel Stelter-Gliese](https://www.linkedin.com/in/daniel-stelter-gliese-170a70a2/).
* [如何正確的取得使用者 IP ？](http://devco.re/blog/2014/06/19/client-ip-detection/) - Written by [Allen Own](http://devco.re/blog/author/allenown).
* [1000php](https://github.com/Xyntax/1000php) - 1000个PHP代码审计案例(2016.7以前乌云公开漏洞) by [@Xyntax](https://github.com/Xyntax).
* [Brute Forcing Your Facebook Email and Phone Number](http://pwndizzle.blogspot.jp/2014/02/brute-forcing-your-facebook-email-and.html) - Written by [PwnDizzle](http://pwndizzle.blogspot.jp/).
* [GITLEAKS](https://gitleaks.com/) - Search engine for exposed secrets on lots of places.
* [Pentest + Exploit dev Cheatsheet wallpaper](http://i.imgur.com/Mr9pvq9.jpg) - Penetration Testing and Exploit Dev CheatSheet.
* [Hunting for Web Shells](https://www.tenable.com/blog/hunting-for-web-shells) - Written by [Jacob Baines](https://www.tenable.com/profile/jacob-baines).
* [The Definitive Security Data Science and Machine Learning Guide](http://www.covert.io/the-definitive-security-datascience-and-machinelearning-guide/) - Written by JASON TROS.
* [EQGRP](https://github.com/x0rz/EQGRP) - Decrypted content of eqgrp-auction-file.tar.xz by [@x0rz](https://github.com/x0rz).
* [Browser Extension and Login-Leak Experiment](https://extensions.inrialpes.fr/) - Browser Extension and Login-Leak Experiment.
* [notes](https://github.com/ChALkeR/notes) - Some public notes by [@ChALkeR](https://github.com/ChALkeR).
* [The Art of Subdomain Enumeration](https://blog.sweepatic.com/art-of-subdomain-enumeration/) - Written by [Patrik Hudak](https://blog.sweepatic.com/author/patrik/).

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](code-of-conduct.md). By participating in this project you agree to abide by its terms.

## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, [@qazbnm456](https://qazbnm456.github.io/) has waived all copyright and related or neighboring rights to this work.
