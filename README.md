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
- [Evasion](#evasion)
	- [CSP](#evasion-csp)
- [Trick](#trick)
    - [XSS](trick-xss)
    - [SQL Injection](#trick-sql-injection)
- [PoC](#poc)
    - [JavaScript](#poc-javascript)
- [Tool](#tool)
    - [Code Generating](#tool-code-generating)
    - [Fuzzing](#tool-fuzzing)
    - [Leaking](#tool-leaking)
    - [Detecting](#tool-detecting)
- [Blog](#blog)
- [Miscellaneous](#miscellaneous)

## Resource

<a name="resource-xss"></a>
### XSS

* [H5SC](https://github.com/cure53/H5SC)

<a name="resource-sql-injection"></a>
### SQL Injection

* [HQL for pentesters](http://blog.h3xstream.com/2014/02/hql-for-pentesters.html)

<a name="resource-xml"></a>
### XML

* [XML实体攻击 - 从内网探测到命令执行步步惊心](http://www.freebuf.com/video/49961.html), written by 张天琪.

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

## Trick

<a name="trick-xss"></a>
### XSS

* [ECMAScript 6 from an Attacker's Perspective - Breaking Frameworks, Sandboxes, and everything else](http://www.slideshare.net/x00mario/es6-en), written by [Mario Heiderich](http://www.slideshare.net/x00mario).

<a name="trick-sql-injection"></a>
### SQL Injection

* [屌智硬之mysql不用逗号注入](http://www.jinglingshu.org/?p=2220), written by [jinglingshu](http://www.jinglingshu.org/?p=2220).
* [见招拆招：绕过WAF继续SQL注入常用方法](http://www.freebuf.com/articles/web/36683.html), written by [mikey](http://www.freebuf.com/author/mikey).

## PoC

<a name="poc-javascript"></a>
### JavaScript

* [js-vuln-db](https://github.com/tunz/js-vuln-db) - A collection of JavaScript engine CVEs with PoCs by [@tunz][https://github.com/tunz].

## Tool

<a name="tool-code-generating"></a>
### Code Generating

* [VWGen](https://github.com/qazbnm456/VWGen) - Vulnerable Web applications Generator by [@qazbnm456](https://github.com/qazbnm456).

<a name="tool-fuzzing"></a>
### Fuzzing

* [wfuzz](https://github.com/xmendez/wfuzz) - Web application bruteforcer by [@xmendez](https://github.com/xmendez).
* [charsetinspect](https://github.com/hack-all-the-things/charsetinspect) - A script that inspects multi-byte character sets looking for characters with specific user-defined properties by [@hack-all-the-things](https://github.com/hack-all-the-things).

<a name="tool-leaking"></a>
### leaking

* [HTTPLeaks](https://github.com/cure53/HTTPLeaks) - All possible ways, a website can leak HTTP requests by [@cure53](https://github.com/cure53).
* [dvcs-ripper](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN/GIT/HG... by [@kost](https://github.com/kost).

<a name="tool-detecting"></a>
### Detecting

* [sqlchop](https://github.com/chaitin/sqlchop/) - [DEPRECATED] A novel SQL injection detection engine built on top of SQL tokenizing and syntax analysis by [chaitin](http://chaitin.com).
* [retire.js](https://github.com/RetireJS/retire.js) - Scanner detecting the use of JavaScript libraries with known vulnerabilities by [@RetireJS](https://github.com/RetireJS).

## Blog

* [Broken Browser](https://www.brokenbrowser.com/) - Fun with Browser Vulnerabilities.

## Miscellaneous

* [如何正確的取得使用者 IP ？](http://devco.re/blog/2014/06/19/client-ip-detection/), written by [Allen Own](http://devco.re/blog/author/allenown).

## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, [Sindre Sorhus](http://sindresorhus.com) has waived all copyright and related or neighboring rights to this work.