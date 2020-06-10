![alt tag](https://github.com/1N3/IntruderPayloads/blob/master/BurpsuiteIntruderPayloads.png)

# IntruderPayloads
A collection of Burpsuite Intruder payloads, BurpBounty payloads (https://github.com/wagiro/BurpBounty), fuzz lists and pentesting methodologies. To pull down all 3rd party repos, run install.sh in the same directory of the IntruderPayloads folder.

Author: xer0dayz@xerosecurity.com - https://xerosecurity.com

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

