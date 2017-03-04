# Awesome Web Security [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

[<img src="https://upload.wikimedia.org/wikipedia/commons/6/61/HTML5_logo_and_wordmark.svg" align="right" width="70">](https://www.w3.org/TR/html5/)

> 🐶 A curated list of Web Security materials and resources.

*Please read the [contribution guidelines](CONTRIBUTING.md) before contributing.*

---

<p align="center"><b>🌈 Want to strengthen your penetration skills?</b><br>I would recommend to play some <a href="https://github.com/apsdehal/awesome-ctf" target="_blank">awesome-ctf</a>s.</p>

---

Check out my [repos](https://github.com/qazbnm456) 🐾 or say *hi* on my [Twitter](https://twitter.com/qazbnm456).

## Menu

- [Resource](#resource)
    - [XSS](#resource-xss)
    - [SQL Injection](#resource-sql-injection)
    - [XML](#resource-xml)
    - [CSRF](#resource-csrf)
    - [Rails](#resource-rails)
    - [AngularJS](#resource-angularjs)
- [Evasion](#evasion)
	- [CSP](#evasion-csp)
    - [JSMVC](#evasion-jsmvc)
- [Trick](#trick)
    - [Remote Code Execution](#trick-rce)
    - [XSS](#trick-xss)
    - [SQL Injection](#trick-sql-injection)
    - [SSRF](#trick-ssrf)
    - [Header Injection](#trick-header-injection)
- [Browser Exploitation](#browser-exploitation)
- [PoC](#poc)
    - [JavaScript](#poc-javascript)
- [Tool](#tool)
    - [Code Generating](#tool-code-generating)
    - [Disassembler](#tool-disassembler)
    - [Fuzzing](#tool-fuzzing)
    - [Penetrating](#tool-penetrating)
    - [Leaking](#tool-leaking)
    - [Detecting](#tool-detecting)
- [Blog](#blog)
- [Miscellaneous](#miscellaneous)
- [Practice](#practice)
    - [AWS](#practice-aws)
    - [XSS](#practice-xss)

## Resource

<a name="resource-xss"></a>
### XSS

* [H5SC](https://github.com/cure53/H5SC) - HTML5 Security Cheatsheet - A collection of HTML5 related XSS attack vectors by [@cure53](https://github.com/cure53).
* [XSS.png](https://github.com/jackmasa/XSS.png) - A XSS mind map by [@jackmasa](https://github.com/jackmasa).

<a name="resource-sql-injection"></a>
### SQL Injection

* [HQL for pentesters](http://blog.h3xstream.com/2014/02/hql-for-pentesters.html)

<a name="resource-xml"></a>
### XML

* [XML实体攻击 - 从内网探测到命令执行步步惊心](http://www.freebuf.com/video/49961.html), written by 张天琪.

<a name="resource-csrf"></a>
### CSRF

* [讓我們來談談 CSRF](http://blog.techbridge.cc/2017/02/25/csrf-introduction/), written by [TechBridge](http://blog.techbridge.cc/).

<a name="resource-rails"></a>
### Rails

* [Rails 動態樣板路徑的風險](http://devco.re/blog/2015/07/24/the-vulnerability-of-dynamic-render-paths-in-rails/), written by [Shaolin](http://devco.re/blog/author/shaolin/).
* [Rails Security](http://php.ph/wydrops/drops/Rails%20Security%20(%E4%B8%8A).pdf), written by [@qazbnm456](https://github.com/qazbnm456).

<a name="resource-angularjs"></a>
### AngularJS

* [XSS without HTML: Client-Side Template Injection with AngularJS](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html), written by [Gareth Heyes](https://www.blogger.com/profile/10856178524811553475).

## Evasion

<a name="evasion-csp"></a>
### CSP

* [CSP: bypassing form-action with reflected XSS](https://labs.detectify.com/2016/04/04/csp-bypassing-form-action-with-reflected-xss/), written by [Detectify Labs](https://labs.detectify.com/).

<a name="evasion-jsmvc"></a>
### JSMVC

* [JavaScript MVC and Templating Frameworks](http://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks), written by [Mario Heiderich](http://www.slideshare.net/x00mario).

## Trick

<a name="trick-rce"></a>
### Remote Code Execution

* [Exploiting Node.js deserialization bug for Remote Code Execution](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/), written by [OpSecX](https://opsecx.com/index.php/author/ajinabraham/).

<a name="trick-xss"></a>
### XSS

* [ECMAScript 6 from an Attacker's Perspective - Breaking Frameworks, Sandboxes, and everything else](http://www.slideshare.net/x00mario/es6-en), written by [Mario Heiderich](http://www.slideshare.net/x00mario).

<a name="trick-sql-injection"></a>
### SQL Injection

* [屌智硬之mysql不用逗号注入](http://www.jinglingshu.org/?p=2220), written by [jinglingshu](http://www.jinglingshu.org/?p=2220).
* [见招拆招：绕过WAF继续SQL注入常用方法](http://www.freebuf.com/articles/web/36683.html), written by [mikey](http://www.freebuf.com/author/mikey).
* [MySQL Error Based SQL  Injection Using  EXP](https://www.exploit-db.com/docs/37953.pdf), written by [@osandamalith](https://twitter.com/osandamalith).
* [SQL injection in an UPDATE query - a bug bounty story!](http://zombiehelp54.blogspot.jp/2017/02/sql-injection-in-update-query-bug.html), written by [Zombiehelp54](http://zombiehelp54.blogspot.jp/).

<a name="trick-ssrf"></a>
### SSRF

* [SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748), written by [aesteral](https://hackerone.com/aesteral).

<a name="trick-header-injection"></a>
### Header Injection

* [Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html), written by [Timothy Morgan](https://plus.google.com/105917618099766831589).

## Browser Exploitation

* [First Step to Browser Exploitation](http://mashirogod.dothome.co.kr/index.php/2017/01/07/first-step-to-browser-exploitation/), written by [Brian Pak](http://mashirogod.dothome.co.kr/).

## PoC

<a name="poc-javascript"></a>
### JavaScript

* [js-vuln-db](https://github.com/tunz/js-vuln-db) - A collection of JavaScript engine CVEs with PoCs by [@tunz](https://github.com/tunz).
* [awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc) - A curated list of CVE PoCs by [@qazbnm456](https://github.com/qazbnm456).

## Tool

<a name="tool-code-generating"></a>
### Code Generating

* [VWGen](https://github.com/qazbnm456/VWGen) - Vulnerable Web applications Generator by [@qazbnm456](https://github.com/qazbnm456).

<a name="tool-disassembler"></a>
### Disassembler

* [plasma](https://github.com/plasma-disassembler/plasma) - Plasma is an interactive disassembler for x86/ARM/MIPS by [@plasma-disassembler](https://github.com/plasma-disassembler).
* [radare2](https://github.com/radare/radare2) - unix-like reverse engineering framework and commandline tools by [@radare](https://github.com/radare).

<a name="tool-fuzzing"></a>
### Fuzzing

* [wfuzz](https://github.com/xmendez/wfuzz) - Web application bruteforcer by [@xmendez](https://github.com/xmendez).
* [charsetinspect](https://github.com/hack-all-the-things/charsetinspect) - A script that inspects multi-byte character sets looking for characters with specific user-defined properties by [@hack-all-the-things](https://github.com/hack-all-the-things).
* [IPObfuscator](https://github.com/OsandaMalith/IPObfuscator) - A simple too to convert the IP to a DWORD IP by [@OsandaMalith](https://github.com/OsandaMalith).
* [wpscan](https://github.com/wpscanteam/wpscan) - WPScan is a black box WordPress vulnerability scanner by [@wpscanteam](https://github.com/wpscanteam).
* [JoomlaScan](https://github.com/drego85/JoomlaScan) - A free software to find the components installed in Joomla CMS, built out of the ashes of Joomscan by [@drego85](https://github.com/drego85).

<a name="tool-penetrating"></a>
### Penetrating

* [Burp Suite](https://portswigger.net/burp/) - Burp Suite is an integrated platform for performing security testing of web applications by [portswigger](https://portswigger.net/).
* [mitmproxy](https://github.com/mitmproxy/mitmproxy) - An interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers by [@mitmproxy](https://github.com/mitmproxy).

<a name="tool-leaking"></a>
### Leaking

* [HTTPLeaks](https://github.com/cure53/HTTPLeaks) - All possible ways, a website can leak HTTP requests by [@cure53](https://github.com/cure53).
* [dvcs-ripper](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN/GIT/HG... by [@kost](https://github.com/kost).
* [DVCS-Pillage](https://github.com/evilpacket/DVCS-Pillage) - Pillage web accessible GIT, HG and BZR repositories by [@evilpacket](https://github.com/evilpacket).

<a name="tool-detecting"></a>
### Detecting

* [sqlchop](https://github.com/chaitin/sqlchop/) - [DEPRECATED] A novel SQL injection detection engine built on top of SQL tokenizing and syntax analysis by [chaitin](http://chaitin.com).
* [retire.js](https://github.com/RetireJS/retire.js) - Scanner detecting the use of JavaScript libraries with known vulnerabilities by [@RetireJS](https://github.com/RetireJS).
* [malware-jail](https://github.com/HynekPetrak/malware-jail) - Sandbox for semi-automatic Javascript malware analysis, deobfuscation and payload extraction by [@HynekPetrak](https://github.com/HynekPetrak).

<a name="tool-others"></a>
### Others

* [Dnslogger](https://wiki.skullsecurity.org/index.php?title=Dnslogger) - Dns Logger by [@iagox86](https://github.com/iagox86).

## Blog

* [Orange](http://blog.orange.tw/) - This is Orange Speaking :)
* [Broken Browser](https://www.brokenbrowser.com/) - Fun with Browser Vulnerabilities.
* [Blog of Osanda](https://osandamalith.com/) - Security Researching and Reverse Engineering.

## Miscellaneous

* [awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty) - A comprehensive curated list of available Bug Bounty & Disclosure Programs and write-ups by [@djadmin](https://github.com/djadmin).
* [bug-bounty-reference](https://github.com/ngalongc/bug-bounty-reference) - A list of bug bounty write-up that is categorized by the bug nature by [@ngalongc](https://github.com/ngalongc).
* [如何正確的取得使用者 IP ？](http://devco.re/blog/2014/06/19/client-ip-detection/), written by [Allen Own](http://devco.re/blog/author/allenown).
* [1000php](https://github.com/Xyntax/1000php) - 1000个PHP代码审计案例(2016.7以前乌云公开漏洞) by [@Xyntax](https://github.com/Xyntax).
* [Brute Forcing Your Facebook Email and Phone Number](http://pwndizzle.blogspot.jp/2014/02/brute-forcing-your-facebook-email-and.html), written by [PwnDizzle](http://pwndizzle.blogspot.jp/).
* [GITLEAKS](https://gitleaks.com/) - Search engine for exposed secrets on lots of places.
* [Pentest + Exploit dev Cheatsheet wallpaper](http://i.imgur.com/Mr9pvq9.jpg) - Penetration Testing and Exploit Dev CheatSheet.

## Practice

<a name="practice-aws"></a>
### AWS

* [FLAWS](http://flaws.cloud/) - Amazon AWS CTF challenge, written by [@0xdabbad00](https://twitter.com/0xdabbad00).

<a name="practice-xss"></a>
### XSS

* [alert(1) to win](https://alf.nu/alert1) - A series of XSS challenges, written by [@steike](https://twitter.com/steike).
* [prompt(1) to win](http://prompt.ml/) - A complex 16-Level XSS Challenge held in summer 2014 (+4 Hidden Levels), written by [@cure53](https://github.com/cure53).

## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, [Sindre Sorhus](http://sindresorhus.com) has waived all copyright and related or neighboring rights to this work.