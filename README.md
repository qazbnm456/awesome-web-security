# Awesome Web Security [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

[<img src="https://upload.wikimedia.org/wikipedia/commons/6/61/HTML5_logo_and_wordmark.svg" align="right" width="70">](https://www.w3.org/TR/html5/)

> 🐶 Curated list of Web Security materials and resources.

Needless to say, most websites suffer from various types of bugs which may eventually lead to vulnerabilities. Why would this happen so often? There can be many factors involved including misconfiguration, shortage of engineers' security skills, etc. To combat this, here is a curated list of Web Security materials and resources for learning cutting edge penetrating techniques.

*Please read the [contribution guidelines](CONTRIBUTING.md) before contributing.*

---

<p align="center"><b>🌈 Want to strengthen your penetration skills?</b><br>I would recommend playing some <a href="https://github.com/apsdehal/awesome-ctf" target="_blank">awesome-ctf</a>s.</p>

---

If you enjoy this awesome list and would like to support it, check out my [Patreon](https://www.patreon.com/boik) page :)<br>Also, don't forget to check out my [repos](https://github.com/qazbnm456) 🐾 or say *hi* on my [Twitter](https://twitter.com/qazbnm456)!

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
  - [CSRF](#csrf---cross-site-request-forgery)
  - [SSRF](#ssrf---server-side-request-forgery)
  - [Rails](#rails)
  - [AngularJS](#angularjs)
  - [SSL/TLS](#ssltls)
  - [Webmail](#webmail)
  - [NFS](#nfs)
  - [AWS](#aws)
  - [Fingerprint](#fingerprint)
  - [Sub Domain Enumeration](#sub-domain-enumeration)
  - [Crypto](#crypto)
  - [Web Shell](#web-shell)
  - [OSINT](#osint)
  - [Books](#books)
- [Evasions](#evasions)
  - [CSP](#evasions-csp)
  - [WAF](#evasions-waf)
  - [JSMVC](#evasions-jsmvc)
  - [Authentication](#evasions-authentication)
- [Tricks](#tricks)
  - [CSRF](#tricks-csrf)
  - [Remote Code Execution](#tricks-rce)
  - [XSS](#tricks-xss)
  - [SQL Injection](#tricks-sql-injection)
  - [NoSQL Injection](#tricks-nosql-injection)
  - [FTP Injection](#tricks-ftp-injection)
  - [XXE](#tricks-xxe)
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
    - [OSINT](#tools-osint)
    - [Sub Domain Enumeration](#tools-sub-domain-enumeration)
  - [Code Generating](#tools-code-generating)
  - [Fuzzing](#tools-fuzzing)
  - [Penetrating](#tools-penetrating)
  - [Leaking](#tools-leaking)
  - [Offensive](#tools-offensive)
    - [XSS](#tools-xss)
    - [SQL Injection](#tools-sql-injection)
    - [Template Injection](#tools-template-injection)
  - [Detecting](#tools-detecting)
  - [Preventing](#tools-preventing)
  - [Proxy](#tools-proxy)
  - [Webshell](#tools-webshell)
  - [Disassembler](#tools-disassembler)
  - [Decompiler](#tools-decompiler)
  - [Others](#tools-others)
- [Social Engineering Database](#social-engineering-database)
- [Blogs](#blogs)
- [Twitter Users](#twitter-users)
- [Practices](#practices)
  - [Application](#practices-application)
  - [AWS](#practices-aws)
  - [XSS](#practices-xss)
  - [ModSecurity / OWASP ModSecurity Core Rule Set](#practices-modsecurity)
- [Community](#community)
- [Miscellaneous](#miscellaneous)

## Forums

- [Phrack Magazine](http://www.phrack.org/) - Ezine written by and for hackers.
- [The Hacker News](https://thehackernews.com/) - Security in a serious way.
- [Security Weekly](https://securityweekly.com/) - The security podcast network.
- [The Register](http://www.theregister.co.uk/) - Biting the hand that feeds IT.
- [Dark Reading](https://www.darkreading.com/Default.asp) - Connecting The Information Security Community.
- [HackDig](http://en.hackdig.com/) - Dig high-quality web security articles for hacker.

## Resources

<a name="tips"></a>
### Tips

- [Hacker101](https://www.hacker101.com/) - Written by [hackerone](https://www.hackerone.com/start-hacking).
- [The Daily Swig - Web security digest](https://portswigger.net/daily-swig) - Written by [PortSwigger](https://portswigger.net/).
- [Web Application Security Zone by Netsparker](https://www.netsparker.com/blog/web-security/) - Written by [Netsparker](https://www.netsparker.com/).
- [Infosec Newbie](https://www.sneakymonkey.net/2017/04/23/infosec-newbie/) - Written by [Mark Robinson](https://www.sneakymonkey.net/).
- [The Magic of Learning](https://bitvijays.github.io/) - Written by [@bitvijays](https://bitvijays.github.io/aboutme.html).
- [CTF Field Guide](https://trailofbits.github.io/ctf/) - Written by [Trail of Bits](https://www.trailofbits.com/).

<a name="xss"></a>
### XSS - Cross-Site Scripting

- [Cross-Site Scripting – Application Security – Google](https://www.google.com/intl/sw/about/appsecurity/learning/xss/) - Introduction to XSS by [Google](https://www.google.com/).
- [H5SC](https://github.com/cure53/H5SC) - HTML5 Security Cheatsheet - Collection of HTML5 related XSS attack vectors by [@cure53](https://github.com/cure53).
- [XSS.png](https://github.com/jackmasa/XSS.png) - XSS mind map by [@jackmasa](https://github.com/jackmasa).
- [C.XSS Guide](https://excess-xss.com/) - Comprehensive tutorial on cross-site scripting by [@JakobKallin](https://github.com/JakobKallin) and [Irene Lobo Valbuena](https://www.linkedin.com/in/irenelobovalbuena/).

<a name="csv-injection"></a>
### CSV Injection

- [CSV Injection -> Meterpreter on Pornhub](https://news.webamooz.com/wp-content/uploads/bot/offsecmag/147.pdf) - Written by [Andy](https://blog.zsec.uk/).
- [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html) - Written by [George Mauer](http://georgemauer.net/).

<a name="sql-injection"></a>
### SQL Injection

- [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/) - Written by [@netsparker](https://twitter.com/netsparker).
- [SQL Injection Wiki](https://sqlwiki.netspi.com/) - Written by [NETSPI](https://www.netspi.com/).
- [SQL Injection Pocket Reference](https://websec.ca/kb/sql_injection) - Written by [@LightOS](https://twitter.com/LightOS).

<a name="command-injection"></a>
### Command Injection

- [Potential command injection in resolv.rb](https://github.com/ruby/ruby/pull/1777) - Written by [@drigg3r](https://github.com/drigg3r).

<a name="orm-injection"></a>
### ORM Injection

- [HQL for pentesters](http://blog.h3xstream.com/2014/02/hql-for-pentesters.html) - Written by [@h3xstream](https://twitter.com/h3xstream/).
- [HQL : Hyperinsane Query Language (or how to access the whole SQL API within a HQL injection ?)](https://www.synacktiv.com/ressources/hql2sql_sstic_2015_en.pdf) - Written by [@_m0bius](https://twitter.com/_m0bius).
- [ORM2Pwn: Exploiting injections in Hibernate ORM](https://www.slideshare.net/0ang3el/orm2pwn-exploiting-injections-in-hibernate-orm) - Written by [Mikhail Egorov](https://0ang3el.blogspot.tw/).
- [ORM Injection](https://www.slideshare.net/simone.onofri/orm-injection) - Written by [Simone Onofri](https://onofri.org/).

<a name="ftp-injection"></a>
### FTP Injection

- [Advisory: Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by [Timothy Morgan](https://plus.google.com/105917618099766831589).
- [SMTP over XXE − how to send emails using Java's XML parser](https://shiftordie.de/blog/2017/02/18/smtp-over-xxe/) - Written by [Alexander Klink](https://shiftordie.de/).

<a name="xxe"></a>
### XXE - XML eXternal Entity

- [XXE](https://phonexicum.github.io/infosec/xxe.html) - Written by [@phonexicum](https://twitter.com/phonexicum).

<a name="csrf"></a>
### CSRF - Cross-Site Request Forgery

- [Wiping Out CSRF](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f) - Written by [@jrozner](https://medium.com/@jrozner).

<a name="ssrf"></a>
### SSRF - Server-Side Request Forgery

- [SSRF bible. Cheatsheet](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit) - Written by [@Wallarm](https://twitter.com/wallarm).

<a name="rails"></a>
### Rails

- [Rails Security - First part](https://hackmd.io/s/SkuTVw5O-) - Written by [@qazbnm456](https://github.com/qazbnm456).

<a name="angularjs"></a>
### AngularJS

- [XSS without HTML: Client-Side Template Injection with AngularJS](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html) - Written by [Gareth Heyes](https://www.blogger.com/profile/10856178524811553475).
- [DOM based Angular sandbox escapes](http://blog.portswigger.net/2017/05/dom-based-angularjs-sandbox-escapes.html) - Written by [@garethheyes](https://twitter.com/garethheyes)

<a name="ssl-tls"></a>
### SSL/TLS

- [SSL & TLS Penetration Testing](https://www.aptive.co.uk/blog/tls-ssl-security-testing/) - Written by [APTIVE](https://www.aptive.co.uk/).

<a name="webmail"></a>
### Webmail

<a name="nfs"></a>
### NFS

- [NFS | PENETRATION TESTING ACADEMY](https://pentestacademy.wordpress.com/2017/09/20/nfs/?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=b34422ce15164e99a193fea0ccc7a02f&uid=1959680352&nid=244+289476616) - Written by [PENETRATION ACADEMY](https://pentestacademy.wordpress.com/).

<a name="aws"></a>
### AWS

- [PENETRATION TESTING AWS STORAGE: KICKING THE S3 BUCKET](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/) - Written by Dwight Hohnstein from [Rhino Security Labs](https://rhinosecuritylabs.com/).
- [AWS PENETRATION TESTING PART 1. S3 BUCKETS](https://www.virtuesecurity.com/blog/aws-penetration-testing-s3-buckets/) - Written by [@VirtueSecurity](https://twitter.com/VirtueSecurity).
- [AWS PENETRATION TESTING PART 2. S3, IAM, EC2](https://www.virtuesecurity.com/blog/aws-penetration-testing-part-2-s3-iam-ec2/) - Written by [@VirtueSecurity](https://twitter.com/VirtueSecurity).

<a name="fingerprint"></a>
### Fingerprint

<a name="sub-domain-enumeration"></a>
### Sub Domain Enumeration

- [A penetration tester’s guide to sub-domain enumeration](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6) - Written by [Bharath](https://blog.appsecco.com/@yamakira_).
- [The Art of Subdomain Enumeration](https://blog.sweepatic.com/art-of-subdomain-enumeration/) - Written by [Patrik Hudak](https://blog.sweepatic.com/author/patrik/).

<a name="crypto"></a>
### Crypto

- [Applied Crypto Hardening](https://bettercrypto.org/static/applied-crypto-hardening.pdf) - Written by [The bettercrypto.org Team](https://bettercrypto.org/).

<a name="web-shell"></a>
### Web Shell

- [Hunting for Web Shells](https://www.tenable.com/blog/hunting-for-web-shells) - Written by [Jacob Baines](https://www.tenable.com/profile/jacob-baines).
- [Hacking with JSP Shells](https://blog.netspi.com/hacking-with-jsp-shells/) - Written by [@_nullbind](https://twitter.com/_nullbind).

<a name="osint"></a>
### OSINT

- [Hacking Cryptocurrency Miners with OSINT Techniques](https://medium.com/@s3yfullah/hacking-cryptocurrency-miners-with-osint-techniques-677bbb3e0157) - Written by [@s3yfullah](https://medium.com/@s3yfullah).
- [OSINT x UCCU Workshop on Open Source Intelligence](https://www.slideshare.net/miaoski/osint-x-uccu-workshop-on-open-source-intelligence) - Written by [Philippe Lin](https://www.slideshare.net/miaoski).
- [102 Deep Dive in the Dark Web OSINT Style Kirby Plessas](https://www.youtube.com/watch?v=fzd3zkAI_o4) - Presented by [@kirbstr](https://twitter.com/kirbstr).

### Books

- [XSS Cheat Sheet - 2018 Edition](https://leanpub.com/xss) - Written by [@brutelogic](https://twitter.com/brutelogic).

## Evasions

<a name="evasions-csp"></a>
### CSP

- [CSP: bypassing form-action with reflected XSS](https://labs.detectify.com/2016/04/04/csp-bypassing-form-action-with-reflected-xss/) - Written by [Detectify Labs](https://labs.detectify.com/).
- [TWITTER XSS + CSP BYPASS](http://www.paulosyibelo.com/2017/05/twitter-xss-csp-bypass.html) - Written by [Paulos Yibelo](http://www.paulosyibelo.com/).

<a name="evasions-waf"></a>
### WAF

- [Web Application Firewall (WAF) Evasion Techniques](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8) - Written by [@secjuice](https://twitter.com/secjuice).
- [Web Application Firewall (WAF) Evasion Techniques #2](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0) - Written by [@secjuice](https://twitter.com/secjuice).
- [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/) - Written by [@Brett Buerhaus](https://twitter.com/bbuerhaus).
- [How to bypass libinjection in many WAF/NGWAF](https://medium.com/@d0znpp/how-to-bypass-libinjection-in-many-waf-ngwaf-1e2513453c0f) - Written by [@d0znpp](https://medium.com/@d0znpp).

<a name="evasions-jsmvc"></a>
### JSMVC

- [JavaScript MVC and Templating Frameworks](http://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).

<a name="evasions-authentication"></a>
### Authentication

- [Trend Micro Threat Discovery Appliance - Session Generation Authentication Bypass (CVE-2016-8584)](http://blog.malerisch.net/2017/04/trend-micro-threat-discovery-appliance-session-generation-authentication-bypass-cve-2016-8584.html) - Written by [@malerisch](https://twitter.com/malerisch) and [@steventseeley](https://twitter.com/steventseeley).
- [Yahoo Bug Bounty: Chaining 3 Minor Issues To Takeover Flickr Accounts](http://blog.mish.re/index.php/2017/04/29/yahoo-bug-bounty-chaining-3-minor-issues-to-takeover-flickr-accounts/) - Written by [Mishre](http://blog.mish.re/).

## Tricks

<a name="tricks-csrf"></a>
### CSRF

- [Neat tricks to bypass CSRF-protection](https://zhuanlan.zhihu.com/p/32716181) - Written by [Twosecurity](https://twosecurity.io/).
- [Exploiting CSRF on JSON endpoints with Flash and redirects](https://blog.appsecco.com/exploiting-csrf-on-json-endpoints-with-flash-and-redirects-681d4ad6b31b) - Written by [@riyazwalikar](https://blog.appsecco.com/@riyazwalikar).
- [Stealing CSRF tokens with CSS injection (without iFrames)](https://github.com/dxa4481/cssInjection) - Written by [@dxa4481](https://github.com/dxa4481).

<a name="tricks-rce"></a>
### Remote Code Execution

- [Exploiting Node.js deserialization bug for Remote Code Execution](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) - Written by [OpSecX](https://opsecx.com/index.php/author/ajinabraham/).
- [DRUPAL 7.X SERVICES MODULE UNSERIALIZE() TO RCE](https://www.ambionics.io/blog/drupal-services-module-rce) - Written by [Ambionics Security](https://www.ambionics.io/).
- [How we exploited a remote code execution vulnerability in math.js](https://capacitorset.github.io/mathjs/) - Written by [@capacitorset](https://github.com/capacitorset).
- [GitHub Enterprise Remote Code Execution](http://exablue.de/blog/2017-03-15-github-enterprise-remote-code-execution.html) - Written by [@iblue](https://github.com/iblue).
- [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) - Written by [Orange](http://blog.orange.tw/).
- [How i Hacked into a PayPal's Server - Unrestricted File Upload to Remote Code Execution](http://blog.pentestbegins.com/2017/07/21/hacking-into-paypal-server-remote-code-execution-2017/) - Written by [Vikas Anil Sharma](http://blog.pentestbegins.com/).

<a name="tricks-xss"></a>
### XSS

- [Query parameter reordering causes redirect page to render unsafe URL](https://hackerone.com/reports/293689) - Written by [kenziy](https://hackerone.com/kenziy).
- [ECMAScript 6 from an Attacker's Perspective - Breaking Frameworks, Sandboxes, and everything else](http://www.slideshare.net/x00mario/es6-en) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).
- [How I found a $5,000 Google Maps XSS (by fiddling with Protobuf)](https://medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff#.u50nrzhas) - Written by [@marin_m](https://medium.com/@marin_m).
- [DON'T TRUST THE DOM: BYPASSING XSS MITIGATIONS VIA SCRIPT GADGETS](https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf) - Written by [Sebastian Lekies](https://twitter.com/slekies), [Krzysztof Kotowicz](https://twitter.com/kkotowicz), and [Eduardo Vela](https://twitter.com/sirdarckcat).
- [Uber XSS via Cookie](http://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie/) - Written by [zhchbin](http://zhchbin.github.io/).
- [DOM XSS – auth.uber.com](http://stamone-bug-bounty.blogspot.tw/2017/10/dom-xss-auth_14.html) - Written by [StamOne_](http://stamone-bug-bounty.blogspot.tw/).
- [Stored XSS on Facebook](https://opnsec.com/2018/03/stored-xss-on-facebook/) - Written by [Enguerran Gillier](https://opnsec.com/).

<a name="tricks-sql-injection"></a>
### SQL Injection

- [MySQL Error Based SQL Injection Using EXP](https://www.exploit-db.com/docs/37953.pdf) - Written by [@osandamalith](https://twitter.com/osandamalith).
- [SQL injection in an UPDATE query - a bug bounty story!](http://zombiehelp54.blogspot.jp/2017/02/sql-injection-in-update-query-bug.html) - Written by [Zombiehelp54](http://zombiehelp54.blogspot.jp/).
- [GitHub Enterprise SQL Injection](http://blog.orange.tw/2017/01/bug-bounty-github-enterprise-sql-injection.html) - Written by [Orange](http://blog.orange.tw/).

<a name="tricks-nosql-injection"></a>
### NoSQL Injection

- [GraphQL NoSQL Injection Through JSON Types](https://medium.com/@east5th/graphql-nosql-injection-through-json-types-a1a0a310c759) - Written by [@east5th](https://medium.com/@east5th).

<a name="tricks-ftp-injection"></a>
### FTP Injection

- [XML Out-Of-Band Data Retrieval](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf) - Written by [@a66at](https://twitter.com/a66at) and Alexey Osipov.
- [XXE OOB exploitation at Java 1.7+](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html) - Written by [Ivan Novikov](http://lab.onsec.ru/).

<a name="tricks-xxe"></a>
### XXE

- [Evil XML with two encodings](https://mohemiv.com/all/evil-xml/) - Written by [Arseniy Sharoglazov](https://mohemiv.com/).

<a name="tricks-ssrf"></a>
### SSRF

- [PHP SSRF Techniques](https://medium.com/secjuice/php-ssrf-techniques-9d422cb28d51) - Written by [@themiddleblue](https://medium.com/@themiddleblue).
- [SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748) - Written by [aesteral](https://hackerone.com/aesteral).
- [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) - Written by [Orange](http://blog.orange.tw/).
- [SSRF Tips](http://blog.safebuff.com/2016/07/03/SSRF-Tips/) - Written by [xl7dev](http://blog.safebuff.com/).

<a name="tricks-header-injection"></a>
### Header Injection

- [Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by [Timothy Morgan](https://plus.google.com/105917618099766831589).

<a name="tricks-url"></a>
### URL

- [Some Problems Of URLs](https://noncombatant.org/2017/11/07/problems-of-urls/) - Written by [Chris Palmer](https://noncombatant.org/about/).
- [Phishing with Unicode Domains](https://www.xudongz.com/blog/2017/idn-phishing/) - Written by [Xudong Zheng](https://www.xudongz.com/).
- [Unicode Domains are bad and you should feel bad for supporting them](https://www.vgrsec.com/post20170219.html) - Written by [VRGSEC](https://www.vgrsec.com/).
- [[dev.twitter.com] XSS](http://blog.blackfan.ru/2017/09/devtwittercom-xss.html) - Written by [Sergey Bobrov](http://blog.blackfan.ru/).

<a name="tricks-others"></a>
### Others

- [How I hacked Google’s bug tracking system itself for $15,600 in bounties](https://medium.freecodecamp.org/messing-with-the-google-buganizer-system-for-15-600-in-bounties-58f86cc9f9a5) - Written by [@alex.birsan](https://medium.freecodecamp.org/@alex.birsan).
- [Some Tricks From My Secret Group](https://www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html) - Written by [PHITHON](https://www.leavesongs.com/).
- [Uber Bug Bounty: Gaining Access To An Internal Chat System](http://blog.mish.re/index.php/2017/09/06/uber-bug-bounty-gaining-access-to-an-internal-chat-system/) - Written by [MISHRE](http://blog.mish.re/).
- [Inducing DNS Leaks in Onion Web Services](https://github.com/epidemics-scepticism/writing/blob/master/onion-dns-leaks.md) - Written by [@epidemics-scepticism](https://github.com/epidemics-scepticism).
- [Stored XSS, and SSRF in Google using the Dataset Publishing Language](https://s1gnalcha0s.github.io/dspl/2018/03/07/Stored-XSS-and-SSRF-Google.html) - Written by [@signalchaos](https://twitter.com/signalchaos).

## Browser Exploitation

### Frontend (like CSP bypass, URL spoofing, and something like that)

- [JSON hijacking for the modern web](http://blog.portswigger.net/2016/11/json-hijacking-for-modern-web.html) - Written by [portswigger](https://portswigger.net/).
- [IE11 Information disclosure - local file detection](https://www.facebook.com/ExploitWareLabs/photos/a.361854183878462.84544.338832389513975/1378579648872572/?type=3&theater) - Written by James Lee.
- [SOP bypass / UXSS – Stealing Credentials Pretty Fast (Edge)](https://www.brokenbrowser.com/sop-bypass-uxss-stealing-credentials-pretty-fast/) - Written by [Manuel](https://twitter.com/magicmac2000).
- [Особенности Safari в client-side атаках](https://bo0om.ru/safari-client-side) - Written by [Bo0oM](https://bo0om.ru/author/admin).

### Backend (core of Browser implementation, and often refers to C or C++ part)

- [Attacking JavaScript Engines - A case study of JavaScriptCore and CVE-2016-4622](http://www.phrack.org/papers/attacking_javascript_engines.html) - Written by [phrack@saelo.net](phrack@saelo.net).
- [Three roads lead to Rome](http://blogs.360.cn/360safe/2016/11/29/three-roads-lead-to-rome-2/) - Written by [Luke Viruswalker](http://blogs.360.cn/360safe/author/xsecure/).
- [Exploiting a V8 OOB write.](https://halbecaf.com/2017/05/24/exploiting-a-v8-oob-write/) - Written by [@halbecaf](https://twitter.com/halbecaf).
- [FROM CRASH TO EXPLOIT: CVE-2015-6086 – OUT OF BOUND READ/ASLR BYPASS](http://payatu.com/from-crash-to-exploit/) - Written by [payatu](http://payatu.com/).
- [SSD Advisory – Chrome Turbofan Remote Code Execution](https://blogs.securiteam.com/index.php/archives/3379) - Written by [SecuriTeam Secure Disclosure (SSD)](https://blogs.securiteam.com/).
- [Look Mom, I don't use Shellcode - Browser Exploitation Case Study for Internet Explorer 11](https://labs.bluefrostsecurity.de/files/Look_Mom_I_Dont_Use_Shellcode-WP.pdf) - Written by [@moritzj](http://twitter.com/moritzj).

## PoCs

<a name="pocs-javascript"></a>
### JavaScript

- [js-vuln-db](https://github.com/tunz/js-vuln-db) - Collection of JavaScript engine CVEs with PoCs by [@tunz](https://github.com/tunz).
- [awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc) - Curated list of CVE PoCs by [@qazbnm456](https://github.com/qazbnm456).
- [Some-PoC-oR-ExP](https://github.com/coffeehb/Some-PoC-oR-ExP) - 各种漏洞poc、Exp的收集或编写 by [@coffeehb](https://github.com/coffeehb).
- [uxss-db](https://github.com/Metnew/uxss-db) - Collection of UXSS CVEs with PoCs by [@Metnew](https://github.com/Metnew).

## Tools

<a name="tools-auditing"></a>
### Auditing

- [prowler](https://github.com/Alfresco/prowler) - Tool for AWS security assessment, auditing and hardening by [@Alfresco](https://github.com/Alfresco).
- [A2SV](https://github.com/hahwul/a2sv) - Auto Scanning to SSL Vulnerability by [@hahwul](https://github.com/hahwul).

<a name="tools-reconnaissance"></a>
### Reconnaissance

<a name="tools-osint"></a>
#### OSINT - Open-Source Intelligence

- [Shodan](https://www.shodan.io/) - Shodan is the world's first search engine for Internet-connected devices by [@shodanhq](https://twitter.com/shodanhq).
- [Censys](https://censys.io/) - Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet by [University of Michigan](https://umich.edu/).
- [urlscan.io](https://urlscan.io/) - Service which analyses websites and the resources they request by [@heipei](https://twitter.com/heipei).
- [ZoomEye](https://www.zoomeye.org/) - Cyberspace Search Engine by [@zoomeye_team](https://twitter.com/zoomeye_team).
- [FOFA](https://fofa.so/?locale=en) - Cyberspace Search Engine by [BAIMAOHUI](http://baimaohui.net/).
- [NSFOCUS](https://nti.nsfocus.com/) - THREAT INTELLIGENCE PORTAL by NSFOCUS GLOBAL.
- [FOCA](https://github.com/ElevenPaths/FOCA) - FOCA (Fingerprinting Organizations with Collected Archives) is a tool used mainly to find metadata and hidden information in the documents its scans by [ElevenPaths](https://www.elevenpaths.com/index.html).
- [SpiderFoot](http://www.spiderfoot.net/) - Open source footprinting and intelligence-gathering tool by [@binarypool](https://twitter.com/binarypool).
- [xray](https://github.com/evilsocket/xray) - XRay is a tool for recon, mapping and OSINT gathering from public networks by [@evilsocket](https://github.com/evilsocket).
- [gitrob](https://github.com/michenriksen/Gitrob) - Reconnaissance tool for GitHub organizations by [@michenriksen](https://github.com/michenriksen).
- [GSIL](https://github.com/FeeiCN/GSIL) - Github Sensitive Information Leakage（Github敏感信息泄露）by [@FeeiCN](https://github.com/FeeiCN).
- [raven](https://github.com/0x09AL/raven) - raven is a Linkedin information gathering tool that can be used by pentesters to gather information about an organization employees using Linkedin by [@0x09AL](https://github.com/0x09AL).
- [ReconDog](https://github.com/UltimateHackers/ReconDog) - Recon Dog is an all in one tool for all your basic information gathering needs by [@UltimateHackers](https://github.com/UltimateHackers).
- [Databases - start.me](https://start.me/p/QRENnO/databases) - Various databases which you can use for your OSINT research by [@technisette](https://twitter.com/technisette).
- [peoplefindThor](https://peoplefindthor.dk/) - the easy way to find people on Facebook by [postkassen](mailto:postkassen@oejvind.dk?subject=peoplefindthor.dk comments).
- [tinfoleak](https://github.com/vaguileradiaz/tinfoleak) - The most complete open-source tool for Twitter intelligence analysis by [@vaguileradiaz](https://github.com/vaguileradiaz).
- [OSINT TOOLKIT](https://osinttoolkit.github.io/index.html) - OSINT TOOLKIT by [the OSINT Toolkit Admin Team](https://osinttoolkit.github.io/).

<a name="tools-sub-domain-enumeration"></a>
#### Sub Domain Enumeration

- [EyeWitness](https://github.com/ChrisTruncer/EyeWitness) - EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible by [@ChrisTruncer](https://github.com/ChrisTruncer).
- [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute) - A simple and fast sub domain brute tool for pentesters by [@lijiejie](https://github.com/lijiejie).
- [AQUATONE](https://github.com/michenriksen/aquatone) - Tool for Domain Flyovers by [@michenriksen](https://github.com/michenriksen).
- [domain_analyzer](https://github.com/eldraco/domain_analyzer) - Analyze the security of any domain by finding all the information possible by [@eldraco](https://github.com/eldraco).
- [VirusTotal domain information](https://www.virustotal.com/en/documentation/searching/#getting-domain-information) - Searching for domain information by [VirusTotal](https://www.virustotal.com/).
- [Certificate Transparency](https://github.com/google/certificate-transparency) - Google's Certificate Transparency project fixes several structural flaws in the SSL certificate system by [@google](https://github.com/google).
- [Certificate Search](https://crt.sh/) - Enter an Identity (Domain Name, Organization Name, etc), a Certificate Fingerprint (SHA-1 or SHA-256) or a crt.sh ID to search certificate(s) by [@crtsh](https://github.com/crtsh).
- [GSDF](https://github.com/We5ter/GSDF) - Domain searcher named GoogleSSLdomainFinder by [@We5ter](https://github.com/We5ter).

<a name="tools-code-generating"></a>
### Code Generating

- [VWGen](https://github.com/qazbnm456/VWGen) - Vulnerable Web applications Generator by [@qazbnm456](https://github.com/qazbnm456).

<a name="tools-fuzzing"></a>
### Fuzzing

- [wfuzz](https://github.com/xmendez/wfuzz) - Web application bruteforcer by [@xmendez](https://github.com/xmendez).
- [charsetinspect](https://github.com/hack-all-the-things/charsetinspect) - Script that inspects multi-byte character sets looking for characters with specific user-defined properties by [@hack-all-the-things](https://github.com/hack-all-the-things).
- [IPObfuscator](https://github.com/OsandaMalith/IPObfuscator) - Simple tool to convert the IP to a DWORD IP by [@OsandaMalith](https://github.com/OsandaMalith).
- [wpscan](https://github.com/wpscanteam/wpscan) - WPScan is a black box WordPress vulnerability scanner by [@wpscanteam](https://github.com/wpscanteam).
- [JoomlaScan](https://github.com/drego85/JoomlaScan) - Free software to find the components installed in Joomla CMS, built out of the ashes of Joomscan by [@drego85](https://github.com/drego85).
- [domato](https://github.com/google/domato) - DOM fuzzer by [@google](https://github.com/google).

<a name="tools-penetrating"></a>
### Penetrating

- [Burp Suite](https://portswigger.net/burp/) - Burp Suite is an integrated platform for performing security testing of web applications by [portswigger](https://portswigger.net/).
- [TIDoS-Framework](https://github.com/the-Infected-Drake/TIDoS-Framework) - Web-penetration testing toolkit, presently suited for reconnaissance purposes by [@the-Infected-Drake](https://github.com/the-Infected-Drake).
- [Astra](https://github.com/flipkart-incubator/astra) - Automated Security Testing For REST API's by [@flipkart-incubator](https://github.com/flipkart-incubator).
- [aws_pwn](https://github.com/dagrz/aws_pwn) - A collection of AWS penetration testing junk by [@dagrz](https://github.com/dagrz).

<a name="tools-offensive"></a>
### Offensive

<a name="tools-xss"></a>
#### XSS - Cross-Site Scripting

- [XSStrike](https://github.com/UltimateHackers/XSStrike) - XSStrike is a program which can fuzz and bruteforce parameters for XSS. It can also detect and bypass WAFs by [@UltimateHackers](https://github.com/UltimateHackers).
- [xssor2](https://github.com/evilcos/xssor2) - XSS'OR - Hack with JavaScript by [@evilcos](https://github.com/evilcos).

<a name="tools-sql-injection"></a>
#### SQL Injection

- [sqlmap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool.

<a name="tools-template-injection"></a>
#### Template Injection

- [tqlmap](https://github.com/epinna/tplmap) - Code and Server-Side Template Injection Detection and Exploitation Tool by [@epinna](https://github.com/epinna).

<a name="tools-leaking"></a>
### Leaking

- [HTTPLeaks](https://github.com/cure53/HTTPLeaks) - All possible ways, a website can leak HTTP requests by [@cure53](https://github.com/cure53).
- [dvcs-ripper](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN/GIT/HG... by [@kost](https://github.com/kost).
- [DVCS-Pillage](https://github.com/evilpacket/DVCS-Pillage) - Pillage web accessible GIT, HG and BZR repositories by [@evilpacket](https://github.com/evilpacket).
- [GitMiner](https://github.com/UnkL4b/GitMiner) - Tool for advanced mining for content on Github by [@UnkL4b](https://github.com/UnkL4b).
- [gitleaks](https://github.com/zricethezav/gitleaks) - Searches full repo history for secrets and keys by [@zricethezav](https://github.com/zricethezav).
- [CSS-Keylogging](https://github.com/maxchehab/CSS-Keylogging) - Chrome extension and Express server that exploits keylogging abilities of CSS by [@maxchehab](https://github.com/maxchehab).
- [pwngitmanager](https://github.com/allyshka/pwngitmanager) - Git manager for pentesters by [@allyshka](https://github.com/allyshka).
- [snallygaster](https://github.com/hannob/snallygaster) - Tool to scan for secret files on HTTP servers by [@hannob](https://github.com/hannob).

<a name="tools-detecting"></a>
### Detecting

- [sqlchop](https://sqlchop.chaitin.cn/) - SQL injection detection engine by [chaitin](http://chaitin.com).
- [xsschop](https://xsschop.chaitin.cn/) - XSS detection engine by [chaitin](http://chaitin.com).
- [retire.js](https://github.com/RetireJS/retire.js) - Scanner detecting the use of JavaScript libraries with known vulnerabilities by [@RetireJS](https://github.com/RetireJS).
- [malware-jail](https://github.com/HynekPetrak/malware-jail) - Sandbox for semi-automatic Javascript malware analysis, deobfuscation and payload extraction by [@HynekPetrak](https://github.com/HynekPetrak).
- [repo-supervisor](https://github.com/auth0/repo-supervisor) - Scan your code for security misconfiguration, search for passwords and secrets.
- [bXSS](https://github.com/LewisArdern/bXSS) - bXSS is a simple Blind XSS application adapted from [cure53.de/m](https://cure53.de/m) by [@LewisArdern](https://github.com/LewisArdern).

<a name="tools-preventing"></a>
### Preventing

- [js-xss](https://github.com/leizongmin/js-xss) - Sanitize untrusted HTML (to prevent XSS) with a configuration specified by a Whitelist by [@leizongmin](https://github.com/leizongmin).

<a name="tools-proxy"></a>
### Proxy

- [Charles](https://www.charlesproxy.com/) - HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet.
- [mitmproxy](https://github.com/mitmproxy/mitmproxy) - Interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers by [@mitmproxy](https://github.com/mitmproxy).

<a name="tools-webshell"></a>
### Webshell

- [webshell](https://github.com/tennc/webshell) - This is a webshell open source project by [@tennc](https://github.com/tennc).
- [Weevely](https://github.com/epinna/weevely3) - Weaponized web shell by [@epinna](https://github.com/epinna).
- [Webshell-Sniper](https://github.com/WangYihang/Webshell-Sniper) - Manage your website via terminal by [@WangYihang](https://github.com/WangYihang).
- [Reverse-Shell-Manager](https://github.com/WangYihang/Reverse-Shell-Manager) - Reverse Shell Manager via Terminal [@WangYihang](https://github.com/WangYihang).
- [reverse-shell](https://github.com/lukechilds/reverse-shell) - Reverse Shell as a Service by [@lukechilds](https://github.com/lukechilds).

<a name="tools-disassembler"></a>
### Disassembler

- [plasma](https://github.com/plasma-disassembler/plasma) - Plasma is an interactive disassembler for x86/ARM/MIPS by [@plasma-disassembler](https://github.com/plasma-disassembler).
- [radare2](https://github.com/radare/radare2) - Unix-like reverse engineering framework and commandline tools by [@radare](https://github.com/radare).
- [Iaitō](https://github.com/hteso/iaito) - Qt and C++ GUI for radare2 reverse engineering framework by [@hteso](https://github.com/hteso).

<a name="tools-decompiler"></a>
### Decompiler

- [CFR](http://www.benf.org/other/cfr/) - Another java decompiler by [@LeeAtBenf](https://twitter.com/LeeAtBenf).

<a name="tools-others"></a>
### Others

- [Dnslogger](https://wiki.skullsecurity.org/index.php?title=Dnslogger) - DNS Logger by [@iagox86](https://github.com/iagox86).
- [CyberChef](https://github.com/gchq/CyberChef) - The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis - by [@GCHQ](https://github.com/gchq).

## Social Engineering Database

**use at your own risk**

- [haveibeenpwned](https://haveibeenpwned.com/) - Check if you have an account that has been compromised in a data breach by [Troy Hunt](https://www.troyhunt.com/).
- [databases.today](https://www.databases.today/index.php) - The biggest free-to-download collection of publicly available website databases for security researchers and journalists by [@publicdbhost](https://twitter.com/publicdbhost).
- [mysql-password](http://www.mysql-password.com/database/1) - Database of MySQL hashes.

## Blogs

- [Orange](http://blog.orange.tw/) - Taiwan's talented web penetrator.
- [leavesongs](https://www.leavesongs.com/) - China's talented web penetrator.
- [James Kettle](http://albinowax.skeletonscribe.net/) - Head of Research at [PortSwigger Web Security](https://portswigger.net/).
- [Broken Browser](https://www.brokenbrowser.com/) - Fun with Browser Vulnerabilities.
- [Scrutiny](https://datarift.blogspot.tw/) - Internet Security through Web Browsers by Dhiraj Mishra.
- [Blog of Osanda](https://osandamalith.com/) - Security Researching and Reverse Engineering.
- [BRETT BUERHAUS](https://buer.haus/) - Vulnerability disclosures and rambles on application security.
- [n0tr00t](https://www.n0tr00t.com/) - ~# n0tr00t Security Team.
- [OpnSec](https://opnsec.com/) - Open Mind Security!
- [LoRexxar](https://lorexxar.cn/) - 带着对技术的敬畏之心成长，不安于一隅...
- [Wfox](http://sec2hack.com/) - 技术宅，热衷各种方面。

## Twitter Users

- [@HackwithGitHub](https://twitter.com/HackwithGithub) - Initiative to showcase open source hacking tools for hackers and pentesters
- [@filedescriptor](https://twitter.com/filedescriptor) - Active penetrator often tweets and writes useful articles
- [@cure53berlin](https://twitter.com/cure53berlin) - [Cure53](https://cure53.de/) is a German cybersecurity firm.
- [@XssPayloads](https://twitter.com/XssPayloads) - The wonderland of JavaScript unexpected usages, and more.
- [@kinugawamasato](https://twitter.com/kinugawamasato) - Japanese web penetrator.
- [@h3xstream](https://twitter.com/h3xstream/) - Security Researcher, interested in web security, crypto, pentest, static analysis but most of all, samy is my hero.
- [@garethheyes](https://twitter.com/garethheyes) - English web penetrator.
- [@hasegawayosuke](https://twitter.com/hasegawayosuke) - Japanese javascript security researcher.

## Practices

<a name="practices-application"></a>
### Application

- [BadLibrary](https://github.com/SecureSkyTechnology/BadLibrary) - vulnerable web application for training - Written by [@SecureSkyTechnology](https://github.com/SecureSkyTechnology).
- [Hackxor](http://hackxor.net/) - realistic web application hacking game - Written by [@albinowax](https://twitter.com/albinowax).
- [SELinux Game](http://selinuxgame.org/) - Learn SELinux by doing. Solve Puzzles, show skillz - Written by [@selinuxgame](https://twitter.com/selinuxgame).

<a name="practices-aws"></a>
### AWS

- [FLAWS](http://flaws.cloud/) - Amazon AWS CTF challenge - Written by [@0xdabbad00](https://twitter.com/0xdabbad00).

<a name="practices-xss"></a>
### XSS

- [XSS Thousand Knocks](https://knock.xss.moe/index) - XSS Thousand Knocks - Written by [@yagihashoo](https://twitter.com/yagihashoo).
- [XSS game](https://xss-game.appspot.com/) - Google XSS Challenge - Written by Google.
- [prompt(1) to win](http://prompt.ml/) - Complex 16-Level XSS Challenge held in summer 2014 (+4 Hidden Levels) - Written by [@cure53](https://github.com/cure53).
- [alert(1) to win](https://alf.nu/alert1) - Series of XSS challenges - Written by [@steike](https://twitter.com/steike).
- [XSS Challenges](http://xss-quiz.int21h.jp/) - Series of XSS challenges - Written by yamagata21.

<a name="practices-modsecurity"></a>
### ModSecurity / OWASP ModSecurity Core Rule Set

- [ModSecurity / OWASP ModSecurity Core Rule Set](https://www.netnea.com/cms/apache-tutorials/) - Series of tutorials to install, configure and tune ModSecurity and the Core Rule Set - Written by [@ChrFolini](https://twitter.com/ChrFolini).

## Community

- [Reddit](https://www.reddit.com/r/websecurity/)
- [Stack Overflow](http://stackoverflow.com/questions/tagged/security)

## Miscellaneous

- [awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty) - Comprehensive curated list of available Bug Bounty & Disclosure Programs and write-ups by [@djadmin](https://github.com/djadmin).
- [bug-bounty-reference](https://github.com/ngalongc/bug-bounty-reference) - List of bug bounty write-up that is categorized by the bug nature by [@ngalongc](https://github.com/ngalongc).
- [Google VRP and Unicorns](https://sites.google.com/site/bughunteruniversity/behind-the-scenes/presentations/google-vrp-and-unicorns) - Written by [Daniel Stelter-Gliese](https://www.linkedin.com/in/daniel-stelter-gliese-170a70a2/).
- [Brute Forcing Your Facebook Email and Phone Number](http://pwndizzle.blogspot.jp/2014/02/brute-forcing-your-facebook-email-and.html) - Written by [PwnDizzle](http://pwndizzle.blogspot.jp/).
- [GITLEAKS](https://gitleaks.com/) - Search engine for exposed secrets on lots of places.
- [Pentest + Exploit dev Cheatsheet wallpaper](http://i.imgur.com/Mr9pvq9.jpg) - Penetration Testing and Exploit Dev CheatSheet.
- [The Definitive Security Data Science and Machine Learning Guide](http://www.covert.io/the-definitive-security-datascience-and-machinelearning-guide/) - Written by JASON TROS.
- [EQGRP](https://github.com/x0rz/EQGRP) - Decrypted content of eqgrp-auction-file.tar.xz by [@x0rz](https://github.com/x0rz).
- [Browser Extension and Login-Leak Experiment](https://extensions.inrialpes.fr/) - Browser Extension and Login-Leak Experiment.
- [notes](https://github.com/ChALkeR/notes) - Some public notes by [@ChALkeR](https://github.com/ChALkeR).
- [A glimpse into GitHub's Bug Bounty workflow](https://githubengineering.com/githubs-bug-bounty-workflow/) - Written by [@gregose](https://github.com/gregose).
- [Cybersecurity Campaign Playbook](https://www.belfercenter.org/CyberPlaybook) - Written by [Belfer Center for Science and International Affairs](https://www.belfercenter.org/).
- [Infosec_Reference](https://github.com/rmusser01/Infosec_Reference) - Information Security Reference That Doesn't Suck by [@rmusser01](https://github.com/rmusser01).
- [Internet of Things Scanner](http://iotscanner.bullguard.com/) - Check if your internet-connected devices at home are public on Shodan by [BullGuard](https://www.bullguard.com/).
- [The Bug Hunters Methodology v2.1](https://docs.google.com/presentation/d/1VpRT8dFyTaFpQa9jhehtmGaC7TqQniMSYbUdlHN6VrY/edit?usp=sharing) - Written by [@jhaddix](https://twitter.com/jhaddix).
- [$7.5k Google services mix-up](https://sites.google.com/site/testsitehacking/-7-5k-Google-services-mix-up) - Written by [Ezequiel Pereira](https://sites.google.com/site/testsitehacking/).
- [How I exploited ACME TLS-SNI-01 issuing Let's Encrypt SSL-certs for any domain using shared hosting](https://labs.detectify.com/2018/01/12/how-i-exploited-acme-tls-sni-01-issuing-lets-encrypt-ssl-certs-for-any-domain-using-shared-hosting/) - Written by [@fransrosen](https://twitter.com/fransrosen).
- [TL:DR: VPN leaks users’ IPs via WebRTC. I’ve tested seventy VPN providers and 16 of them leaks users’ IPs via WebRTC (23%)](https://voidsec.com/vpn-leak/) - Written by [voidsec](https://voidsec.com/).
- [Escape and Evasion Egressing Restricted Networks](https://www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks) - Written by [Chris Patten, Tom Steele](info@optiv.com).
- [Be careful what you copy: Invisibly inserting usernames into text with Zero-Width Characters](https://medium.com/@umpox/be-careful-what-you-copy-invisibly-inserting-usernames-into-text-with-zero-width-characters-18b4e6f17b66) - Written by [@umpox](https://medium.com/@umpox).
- [Domato Fuzzer's Generation Engine Internals](https://www.sigpwn.io/blog/2018/4/14/domato-fuzzers-generation-engine-internals) - Written by [sigpwn](https://www.sigpwn.io/).

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](code-of-conduct.md). By participating in this project you agree to abide by its terms.

## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, [@qazbnm456](https://qazbnm456.github.io/) has waived all copyright and related or neighboring rights to this work.
