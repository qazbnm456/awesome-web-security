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
  - [Tips](#tips)
  - [XSS](#xss---cross-site-scripting)
  - [CSV Injection](#csv-injection)
  - [SQL Injection](#sql-injection)
  - [Command Injection](#command-injection)
  - [ORM Injection](#orm-injection)
  - [FTP Injection](#ftp-injection)
  - [XXE](#xxe---xml-external-entity)
  - [CSRF](##csrf---cross-site-request-forgery)
  - [SSRF](#ssrf---server-side-request-forgery)
  - [Rails](#rails)
  - [AngularJS](#angularjs)
  - [SSL/TLS](#ssltls)
  - [Webmail](#webmail)
  - [NFS](#nfs)
  - [AWS](#aws)
  - [Fingerprint](#fingerprint)
  - [Sub-domain Enumeration](#sub-domain-enumeration)
  - [Crypto](#crypto)
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
  - [FTP Injection](#tricks-ftp-injection)
  - [SSRF](#tricks-ssrf)
  - [Header Injection](#tricks-header-injection)
  - [URL](#tricks-url)
  - [Others](#tricks-others)
- [Browser Exploitation](#browser-exploitation)
- [PoCs](#pocs)
  - [JavaScript](#pocs-javascript)
- [Tools](#tools)
  - [Auditing](#tools-auditing)
  - [Reconnaissance](#tools-reconnaissance)
  - [Code Generating](#tools-code-generating)
  - [Fuzzing](#tools-fuzzing)
  - [Penetrating](#tools-penetrating)
  - [Leaking](#tools-leaking)
  - [Offensive](#tools-offensive)
    - [Template Injection](#tools-template-injection)
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
  - [ModSecurity / OWASP ModSecurity Core Rule Set](#practices-modsecurity)
- [Community](#community)
- [Miscellaneous](#miscellaneous)

## Forums

* [安全客](https://www.anquanke.com/) - 有思想的安全新媒体 by [360网络攻防实验室](https://weibo.com/360adlab).
* [Paper - 安全技术精粹](http://paper.seebug.org/) - Knowledge base for hacking technology built by 404 Team from [knownsec](https://www.knownsec.com/).
* [Freebuf](http://www.freebuf.com/) - Freebuf is the most popular forum in China for exchanging and sharing hacking technology.
* [指尖安全](https://www.secfree.com/) - 垂直互联网安全媒体 by [指尖安全](指尖安全).
* [安全脉搏](https://www.secpulse.com/) - Blog for Security things.
* [破壳（Beta）](https://pockr.org/) - 能看漏洞报告的安全社区 by [SOBUG漏洞悬赏平台](https://sobug.com/).
* [Drops (backup)](https://drops.secquan.org/) - Drops was known as a famous knowledge base for hacking technology.
* [HackDig](http://en.hackdig.com/) - Dig high-quality web security articles for hacker.
* [T00LS](https://www.t00ls.net/) - T00LS - 低调求发展 - 潜心习安全.

## Resources

<a name="tips"></a>
### Tips

* [The Daily Swig - Web security digest](https://portswigger.net/daily-swig) - Written by [PortSwigger](https://portswigger.net/).
* [腾讯玄武实验室安全动态推送](https://xuanwulab.github.io/cn/secnews/2018/01/01/index.html) - Written by [腾讯玄武实验室](http://xlab.tencent.com/cn/).
* [Infosec Newbie](https://www.sneakymonkey.net/2017/04/23/infosec-newbie/) - Written by [Mark Robinson](https://www.sneakymonkey.net/).
* [The Magic of Learning](https://bitvijays.github.io/) - Written by [@bitvijays](https://bitvijays.github.io/aboutme.html).
* [CTF Field Guide](https://trailofbits.github.io/ctf/) - Written by [Trail of Bits](https://www.trailofbits.com/).
* [Got Your PW](https://gotyour.pw/) - Written by [@s3131212](https://github.com/s3131212).

<a name="xss"></a>
### XSS - Cross-Site Scripting

* [Cross-Site Scripting – Application Security – Google](https://www.google.com/intl/sw/about/appsecurity/learning/xss/) - Introduction to XSS by [Google](https://www.google.com/).
* [H5SC](https://github.com/cure53/H5SC) - HTML5 Security Cheatsheet - Collection of HTML5 related XSS attack vectors by [@cure53](https://github.com/cure53).
* [XSS.png](https://github.com/jackmasa/XSS.png) - XSS mind map by [@jackmasa](https://github.com/jackmasa).
* [C.XSS Guide](https://excess-xss.com/) - Comprehensive tutorial on cross-site scripting by [@JakobKallin](https://github.com/JakobKallin) and [Irene Lobo Valbuena](https://www.linkedin.com/in/irenelobovalbuena/).
* [A talk about XSS thousand knocks](https://speakerdeck.com/yagihashoo/a-talk-about-xss-thousand-knocks-shibuya-dot-xss-techtalk-number-10) - Shibuya.XSS techtalk#10 by [Yu Yagihashi](https://speakerdeck.com/yagihashoo).

<a name="csv-injection"></a>
### CSV Injection

* [CSV Injection -> Meterpreter on Pornhub](https://news.webamooz.com/wp-content/uploads/bot/offsecmag/147.pdf) - Written by [Andy](https://blog.zsec.uk/).
* [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html) - Written by [George Mauer](http://georgemauer.net/).

<a name="sql-injection"></a>
### SQL Injection

* [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/) - Written by [@netsparker](https://twitter.com/netsparker).
* [SQL Injection Wiki](https://sqlwiki.netspi.com/) - Written by [NETSPI](https://www.netspi.com/).
* [SQL Injection Pocket Reference](https://websec.ca/kb/sql_injection) - Written by [@LightOS](https://twitter.com/LightOS).

<a name="command-injection"></a>
### Command Injection

* [rubyでopenコマンドを使用するときに気をつけること](http://www.lanches.co.jp/blog/5996) - Written by [金子 将範](http://www.lanches.co.jp/author/rubyist).
* [Potential command injection in resolv.rb](https://github.com/ruby/ruby/pull/1777) - Written by [@drigg3r](https://github.com/drigg3r).

<a name="orm-injection"></a>
### ORM Injection

* [HQL for pentesters](http://blog.h3xstream.com/2014/02/hql-for-pentesters.html) - Written by [@h3xstream](https://twitter.com/h3xstream/).
* [HQL : Hyperinsane Query Language (or how to access the whole SQL API within a HQL injection ?)](https://www.synacktiv.com/ressources/hql2sql_sstic_2015_en.pdf) - Written by [@_m0bius](https://twitter.com/_m0bius).
* [ORM2Pwn: Exploiting injections in Hibernate ORM](https://www.slideshare.net/0ang3el/orm2pwn-exploiting-injections-in-hibernate-orm) - Written by [Mikhail Egorov](https://0ang3el.blogspot.tw/).
* [ORM Injection](https://www.slideshare.net/simone.onofri/orm-injection) - Written by [Simone Onofri](https://onofri.org/).

<a name="ftp-injection"></a>
### FTP Injection

* [Advisory: Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by [Timothy Morgan](https://plus.google.com/105917618099766831589).
* [SMTP over XXE − how to send emails using Java's XML parser](https://shiftordie.de/blog/2017/02/18/smtp-over-xxe/) - Written by [Alexander Klink](https://shiftordie.de/).

<a name="xxe"></a>
### XXE - XML eXternal Entity

* [XXE](https://phonexicum.github.io/infosec/xxe.html) - Written by [@phonexicum](https://twitter.com/phonexicum).
* [XML实体攻击 - 从内网探测到命令执行步步惊心](http://www.freebuf.com/video/49961.html) - Written by 张天琪.
* [XXE漏洞的简单理解和测试](https://b1ngz.github.io/XXE-learning-note/) - Written by [@b1ngz](https://b1ngz.github.io/).

<a name="csrf"></a>
### CSRF - Cross-Site Request Forgery

* [Wiping Out CSRF](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f) - Written by [Joe Rozner](https://medium.com/@jrozner).
* [讓我們來談談 CSRF](http://blog.techbridge.cc/2017/02/25/csrf-introduction/) - Written by [TechBridge](http://blog.techbridge.cc/).

<a name="ssrf"></a>
### SSRF - Server-Side Request Forgery

* [SSRF bible. Cheatsheet](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit) - Written by [@Wallarm](https://twitter.com/wallarm).

<a name="rails"></a>
### Rails

* [Rails 動態樣板路徑的風險](http://devco.re/blog/2015/07/24/the-vulnerability-of-dynamic-render-paths-in-rails/) - Written by [Shaolin](http://devco.re/blog/author/shaolin/).
* [Rails Security - First part](https://hackmd.io/s/SkuTVw5O-) - Written by [@qazbnm456](https://github.com/qazbnm456).

<a name="angularjs"></a>
### AngularJS

* [XSS without HTML: Client-Side Template Injection with AngularJS](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html) - Written by [Gareth Heyes](https://www.blogger.com/profile/10856178524811553475).
* [DOM based Angular sandbox escapes](http://blog.portswigger.net/2017/05/dom-based-angularjs-sandbox-escapes.html) - Written by [@garethheyes](https://twitter.com/garethheyes)

<a name="ssl-tls"></a>
### SSL/TLS

* [SSL & TLS Penetration Testing](https://www.aptive.co.uk/blog/tls-ssl-security-testing/) - Written by [APTIVE](https://www.aptive.co.uk/).

<a name="webmail"></a>
### Webmail

* [Webmail-Hacking](https://github.com/mottoin/SecPaper/blob/master/Webmail-Hacking.pdf) - Written by [千域千寻](http://blog.csdn.net/f1n4lly/).

<a name="nfs"></a>
### NFS

* [NFS | PENETRATION TESTING ACADEMY](https://pentestacademy.wordpress.com/2017/09/20/nfs/?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=b34422ce15164e99a193fea0ccc7a02f&uid=1959680352&nid=244+289476616) - Written by [PENETRATION ACADEMY](https://pentestacademy.wordpress.com/).

<a name="aws"></a>
### AWS

* [PENETRATION TESTING AWS STORAGE: KICKING THE S3 BUCKET](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/) - Written by Dwight Hohnstein from [Rhino Security Labs](https://rhinosecuritylabs.com/).

<a name="fingerprint"></a>
### Fingerprint

* [浅谈Web客户端追踪](http://www.freebuf.com/articles/web/127266.html) - Written by [arkteam](http://www.freebuf.com/author/arkteam).

<a name="sub-domain-enumeration"></a>
### Sub-domain Enumeration

* [A penetration tester’s guide to sub-domain enumeration](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6) - Written by [Bharath](https://blog.appsecco.com/@yamakira_).

<a name="crypto"></a>
### Crypto

* [Applied Crypto Hardening](https://bettercrypto.org/static/applied-crypto-hardening.pdf) - Written by [The bettercrypto.org Team](https://bettercrypto.org/).

### Books

* [Security Geek 2016 - Part. A](http://bobao.360.cn/download/book/security-geek-2016-A.pdf) - Written by [360网络攻防实验室](https://weibo.com/360adlab).
* [Security Geek 2016 - Part. B](http://bobao.360.cn/download/book/security-geek-2016-B.pdf) - Written by [360网络攻防实验室](https://weibo.com/360adlab).
* [Security Geek 2017 - Q1](http://bobao.360.cn/download/book/security-geek-2017-q1.pdf) - Written by [360网络攻防实验室](https://weibo.com/360adlab).
* [Security Geek 2017 - Q2](http://bobao.360.cn/download/book/security-geek-2017-q2.pdf) - Written by [360网络攻防实验室](https://weibo.com/360adlab).
* [Security Geek 2017 - Q3](http://bobao.360.cn/download/book/security-geek-2017-q3.pdf) - Written by [360网络攻防实验室](https://weibo.com/360adlab).
* [Security Geek 2017 - Q4](https://static.anquanke.com/download/b/security-geek-2017-q4.pdf) - Written by [360网络攻防实验室](https://weibo.com/360adlab).

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
* [DOM XSS – auth.uber.com](http://stamone-bug-bounty.blogspot.tw/2017/10/dom-xss-auth_14.html) - Written by [StamOne_](http://stamone-bug-bounty.blogspot.tw/).
* [5文字で書くJavaScript](https://speakerdeck.com/masatokinugawa/shibuya-dot-xss-techtalk-number-10) - Shibuya.XSS techtalk #10 by [Masato Kinugawa](https://twitter.com/kinugawamasato).

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

<a name="tricks-ftp-injection"></a>
### FTP Injection

* [XML Out-Of-Band Data Retrieval](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf) - Written by [@a66at](https://twitter.com/a66at) and Alexey Osipov.
* [XXE OOB exploitation at Java 1.7+](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html) - Written by [Ivan Novikov](http://lab.onsec.ru/).

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

* [Some Problems Of URLs](https://noncombatant.org/2017/11/07/problems-of-urls/) - Written by [Chris Palmer](https://noncombatant.org/about/).
* [URL Hacking - 前端猥琐流](http://php.ph/wydrops/drops/URL%20Hacking%20-%20前端猥琐流.pdf) - Written by [0x_Jin](http://xssec.lofter.com/).
* [Phishing with Unicode Domains](https://www.xudongz.com/blog/2017/idn-phishing/) - Written by [Xudong Zheng](https://www.xudongz.com/).
* [Unicode Domains are bad and you should feel bad for supporting them](https://www.vgrsec.com/post20170219.html) - Written by [VRGSEC](https://www.vgrsec.com/).
* [[dev.twitter.com] XSS](http://blog.blackfan.ru/2017/09/devtwittercom-xss.html) - Written by [Sergey Bobrov](http://blog.blackfan.ru/).

<a name="tricks-others"></a>
### Others

* [How I hacked Google’s bug tracking system itself for $15,600 in bounties](https://medium.freecodecamp.org/messing-with-the-google-buganizer-system-for-15-600-in-bounties-58f86cc9f9a5) - Written by [@alex.birsan](https://medium.freecodecamp.org/@alex.birsan).
* [Some Tricks From My Secret Group](https://www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html) - Written by [PHITHON](https://www.leavesongs.com/).
* [CTF比赛总是输？你还差点Tricks!](https://docs.google.com/presentation/d/1Cx0vI2Mzy0zwdTrgic3S3TwGMCpH-QhMUdHU1r3AYfI/edit#slide=id.g35f391192_065) - Written by [PHITHON](https://www.leavesongs.com/).
* [隱匿的攻擊之-Domain Fronting](https://evi1cg.me/archives/Domain_Fronting.html) - Written by [Evi1cg](https://evi1cg.me/).
* [Uber Bug Bounty: Gaining Access To An Internal Chat System](http://blog.mish.re/index.php/2017/09/06/uber-bug-bounty-gaining-access-to-an-internal-chat-system/) - Written by [MISHRE](http://blog.mish.re/).
* [Inducing DNS Leaks in Onion Web Services](https://github.com/epidemics-scepticism/writing/blob/master/onion-dns-leaks.md) - Written by [@epidemics-scepticism](https://github.com/epidemics-scepticism).

## Browser Exploitation

### Frontend (like CSP bypass, URL spoofing, and something like that)

* [浏览器漏洞挖掘思路](https://zhuanlan.zhihu.com/p/28719766) - Written by [Twosecurity](https://twosecurity.io/).
* [Browser UI Security 技术白皮书](http://xlab.tencent.com/cn/wp-content/uploads/2017/10/browser-ui-security-whitepaper.pdf) - Written by [腾讯玄武实验室](http://xlab.tencent.com/).
* [JSON hijacking for the modern web](http://blog.portswigger.net/2016/11/json-hijacking-for-modern-web.html) - Written by [portswigger](https://portswigger.net/).
* [IE11 Information disclosure - local file detection](https://www.facebook.com/ExploitWareLabs/photos/a.361854183878462.84544.338832389513975/1378579648872572/?type=3&theater) - Written by James Lee.
* [SOP bypass / UXSS – Stealing Credentials Pretty Fast (Edge)](https://www.brokenbrowser.com/sop-bypass-uxss-stealing-credentials-pretty-fast/) - Written by [Manuel](https://twitter.com/magicmac2000).
* [ブラウザの脆弱性とそのインパクト](https://speakerdeck.com/nishimunea/burauzafalsecui-ruo-xing-tosofalseinpakuto) - Written by [Muneaki Nishimura](https://speakerdeck.com/nishimunea) and [Masato Kinugawa](https://twitter.com/kinugawamasato).
* [Особенности Safari в client-side атаках](https://bo0om.ru/safari-client-side) - Written by [Bo0oM](https://bo0om.ru/author/admin).

### Backend (core of Browser implementation, and often refers to C or C++ part)

* [First Step to Browser Exploitation](http://mashirogod.dothome.co.kr/index.php/2017/01/07/first-step-to-browser-exploitation/) - Written by [Brian Pak](http://mashirogod.dothome.co.kr/).
* [Attacking JavaScript Engines - A case study of JavaScriptCore and CVE-2016-4622](http://www.phrack.org/papers/attacking_javascript_engines.html) - Written by [phrack@saelo.net](phrack@saelo.net).
* [Three roads lead to Rome](http://blogs.360.cn/360safe/2016/11/29/three-roads-lead-to-rome-2/) - Written by [Luke Viruswalker](http://blogs.360.cn/360safe/author/xsecure/).
* [Exploiting a V8 OOB write.](https://halbecaf.com/2017/05/24/exploiting-a-v8-oob-write/) - Written by [@halbecaf](https://twitter.com/halbecaf).
* [FROM CRASH TO EXPLOIT: CVE-2015-6086 – OUT OF BOUND READ/ASLR BYPASS](http://payatu.com/from-crash-to-exploit/) - Written by [payatu](http://payatu.com/).
* [SSD Advisory – Chrome Turbofan Remote Code Execution](https://blogs.securiteam.com/index.php/archives/3379) - Written by [SecuriTeam Secure Disclosure (SSD)](https://blogs.securiteam.com/).

## PoCs

<a name="pocs-javascript"></a>
### JavaScript

* [js-vuln-db](https://github.com/tunz/js-vuln-db) - Collection of JavaScript engine CVEs with PoCs by [@tunz](https://github.com/tunz).
* [awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc) - Curated list of CVE PoCs by [@qazbnm456](https://github.com/qazbnm456).
* [Some-PoC-oR-ExP](https://github.com/coffeehb/Some-PoC-oR-ExP) - 各种漏洞poc、Exp的收集或编写 by [@coffeehb](https://github.com/coffeehb).

## Tools

<a name="tools-auditing"></a>
### Auditing

* [prowler](https://github.com/Alfresco/prowler) - Tool for AWS security assessment, auditing and hardening by [@Alfresco](https://github.com/Alfresco).

<a name="tools-reconnaissance"></a>
### Reconnaissance

* [FOCA](https://github.com/ElevenPaths/FOCA) - FOCA (Fingerprinting Organizations with Collected Archives) is a tool used mainly to find metadata and hidden information in the documents its scans by [ElevenPaths](https://www.elevenpaths.com/index.html).
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

<a name="tools-offensive"></a>
### Offensive

<a name="introductions-template-injection"></a>
#### Template Injection

* [tqlmap](https://github.com/epinna/tplmap) - Code and Server-Side Template Injection Detection and Exploitation Tool by [@epinna](https://github.com/epinna).

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
* [bXSS](https://github.com/LewisArdern/bXSS) - bXSS is a simple Blind XSS application adapted from [cure53.de/m](https://cure53.de/m) by [@LewisArdern](https://github.com/LewisArdern).

<a name="tools-preventing"></a>
### Preventing

* [js-xss](https://github.com/leizongmin/js-xss) - Sanitize untrusted HTML (to prevent XSS) with a configuration specified by a Whitelist by [@leizongmin](https://github.com/leizongmin).

<a name="tools-webshell"></a>
### Webshell

* [webshell](https://github.com/tennc/webshell) - This is a webshell open source project by [@tennc](https://github.com/tennc).
* [Weevely](https://github.com/epinna/weevely3) - Weaponized web shell by [@epinna](https://github.com/epinna).
* [Webshell-Sniper](https://github.com/WangYihang/Webshell-Sniper) - Manage your website via terminal by [@WangYihang](https://github.com/WangYihang).
* [Reverse-Shell-Manager](https://github.com/WangYihang/Reverse-Shell-Manager) - Reverse Shell Manager via Terminal [@WangYihang](https://github.com/WangYihang).
* [Linux后门整理合集（脉搏推荐）](https://www.secpulse.com/archives/59674.html) - Written by [armyzer0](https://www.secpulse.com/archives/author/armyzer0).

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
* [databases.today](https://www.databases.today/index.php) - The biggest free-to-download collection of publicly available website databases for security researchers and journalists by [@publicdbhost](https://twitter.com/publicdbhost).
* [70 SECURITY TEAM Social Engineering Data](http://s.70sec.com/) - 70 SECURITY TEAM 社工库 by [70 Security Team](http://70sec.com/).
* [mysql-password](http://www.mysql-password.com/database/1) - Database of MySQL hashes.

## Blogs

* [Orange](http://blog.orange.tw/) - Taiwan's talented web penetrator.
* [leavesongs](https://www.leavesongs.com/) - China's talented web penetrator.
* [James Kettle](http://albinowax.skeletonscribe.net/) - Head of Research at [PortSwigger Web Security](https://portswigger.net/).
* [Broken Browser](https://www.brokenbrowser.com/) - Fun with Browser Vulnerabilities.
* [Scrutiny](https://datarift.blogspot.tw/) - Internet Security through Web Browsers by Dhiraj Mishra.
* [Blog of Osanda](https://osandamalith.com/) - Security Researching and Reverse Engineering.
* [BRETT BUERHAUS](https://buer.haus/) - Vulnerability disclosures and rambles on application security.
* [n0tr00t](https://www.n0tr00t.com/) - ~# n0tr00t Security Team.
* [OpnSec](https://opnsec.com/) - Open Mind Security!
* [LoRexxar](https://lorexxar.cn/) - 带着对技术的敬畏之心成长，不安于一隅...
* [Wfox](http://sec2hack.com/) - 技术宅，热衷各种方面。

## Twitter Users

* [@HackwithGitHub](https://twitter.com/HackwithGithub) - Initiative to showcase open source hacking tools for hackers and pentesters
* [@filedescriptor](https://twitter.com/filedescriptor) - Active penetrator often tweets and writes useful articles
* [@cure53berlin](https://twitter.com/cure53berlin) - [Cure53](https://cure53.de/) is a German cybersecurity firm.
* [@XssPayloads](https://twitter.com/XssPayloads) - The wonderland of JavaScript unexpected usages, and more.
* [@kinugawamasato](https://twitter.com/kinugawamasato) - Japanese web penetrator.
* [@h3xstream](https://twitter.com/h3xstream/) - Security Researcher, interested in web security, crypto, pentest, static analysis but most of all, samy is my hero.
* [@garethheyes](https://twitter.com/garethheyes) - English web penetrator.
* [@hasegawayosuke](https://twitter.com/hasegawayosuke) - Japanese javascript security researcher.

## Practices

<a name="practices-application"></a>
### Application

* [BadLibrary](https://github.com/SecureSkyTechnology/BadLibrary) - vulnerable web application for training - Written by [@SecureSkyTechnology](https://github.com/SecureSkyTechnology).
* [Hackxor](http://hackxor.net/) - realistic web application hacking game - Written by [@albinowax](https://twitter.com/albinowax).

<a name="practices-aws"></a>
### AWS

* [FLAWS](http://flaws.cloud/) - Amazon AWS CTF challenge - Written by [@0xdabbad00](https://twitter.com/0xdabbad00).

<a name="practices-xss"></a>
### XSS

* [XSS Thousand Knocks](https://knock.xss.moe/index) - XSS Thousand Knocks - Written by [@yagihashoo](https://twitter.com/yagihashoo).
* [XSS game](https://xss-game.appspot.com/) - Google XSS Challenge - Written by Google.
* [prompt(1) to win](http://prompt.ml/) - Complex 16-Level XSS Challenge held in summer 2014 (+4 Hidden Levels) - Written by [@cure53](https://github.com/cure53).
* [alert(1) to win](https://alf.nu/alert1) - Series of XSS challenges - Written by [@steike](https://twitter.com/steike).
* [XSS Challenges](http://xss-quiz.int21h.jp/) - Series of XSS challenges - Written by yamagata21.

<a name="practices-modsecurity"></a>
### ModSecurity / OWASP ModSecurity Core Rule Set

* [ModSecurity / OWASP ModSecurity Core Rule Set](https://www.netnea.com/cms/apache-tutorials/) - Series of tutorials to install, configure and tune ModSecurity and the Core Rule Set - Written by [@ChrFolini](https://twitter.com/ChrFolini).

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
* [A glimpse into GitHub's Bug Bounty workflow](https://githubengineering.com/githubs-bug-bounty-workflow/) - Written by [@gregose](https://github.com/gregose).
* [暗网系列之：利用Dark Web Report + EyeWitness+ TorGhost +Docker，自动化获取暗网站点的信息](http://www.mottoin.com/106687.html) - Written by [鹰小编](http://www.mottoin.com/user/ying/).
* [Hacking Cryptocurrency Miners with OSINT Techniques](https://medium.com/@s3yfullah/hacking-cryptocurrency-miners-with-osint-techniques-677bbb3e0157) - Written by [@s3yfullah](https://medium.com/@s3yfullah).

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](code-of-conduct.md). By participating in this project you agree to abide by its terms.

## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, [@qazbnm456](https://qazbnm456.github.io/) has waived all copyright and related or neighboring rights to this work.
