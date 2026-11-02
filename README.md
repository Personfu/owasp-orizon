# The Owasp Orizon project

[Owasp Orizon](http://www.owasp.org/index.php/Category:OWASP_Orizon_Project) is
a source code static analyzer tool designed to spot security issues in Java
applications.

## The history

It was a dark and stormy night in Milan, Italy. It was 2006 and I felt the need
of something helping me in reviewing other people java source code. So Owasp
Orizon born and grew up as security tool trying to parse Java source code,
building an Abstract Syntax Tree and spot for unsafe calls in the code.

In the very beginning Owasp Orizon was a sort of enhanced grep tool. In 2008, I
started supporting PHP programming language but the initial boost disappeared.
After being in love with other programming languages and technolgies, eight
years later, in 2016 I kickstarted the project again from scratch.

## The typo

## The mission

Source code contains bugs and vulnerabilities. Owasp Orizon will help either
application security specialists or developersto spot vulnerabilities in their
code and to create security patches.

Owasp Orizon mission is to provide people an opensource tool, helping them in
reviewing:

* single Java classes
* java standalone tools packed in JAR files
* web applications packed in EAR / WAR files
* Android APK applications

## An overall introduction

When you launch Owasp Orizon it will start unpkacing the target file if not a
standalone .class file.

First security analysis stage is about vulnerabilities from third party
libraries. Owasp Orizon will try to understand target package dependencies and
than look for known security issues.

As knowledge base for third party library vulnerabilities, Owasp Orizon will
support:

* [vFeed.io database](https://vfeed.io). Please note that we don't redistribute
  the database. You must go on [vFeed website](https://vfeed.io) and purchase
  the license that best fits your tool usage
* CVE archive from [NVD](https://nvd.nist.gov)

After this stage, Owasp Orizon will perform a walkthrough on Owasp TOP 10
security risks, using Apache BCEL library to disassemble java bytecode.

## Usage

_More a reminder than a real doc here_

java -Dlog4j.configurationFile=./log4j2.xml -jar target/owasp-orizon-1.0-SNAPSHOT.jar

## The overall design

_To be written_

## Logging security maintenance

The application's own logging dependencies previously used Log4j 2.6.2. These
are runtime dependencies of the analyzer, not intentionally vulnerable target
fixtures. Both `log4j-api` and `log4j-core` now share version 2.26.1 through one
Maven property. This removes the affected Log4Shell versions tracked by
CVE-2021-44228 and CVE-2021-45046 in CISA's Known Exploited Vulnerabilities catalog.

Build with Java 8 or later and `mvn verify`. Check `mvn dependency:tree
-Dincludes=org.apache.logging.log4j` and the packaged JAR before replacing an
installed analyzer; old downloaded JARs are not updated by this source change.
CI builds the project on Java 8 and Java 17. The existing test is only a smoke
test; it does not establish comprehensive analysis or archive-parsing safety.
Other old dependencies and the unpacking/analysis code still require review.

Sources: [Apache Log4j security advisories](https://logging.apache.org/security.html),
[Log4j releases](https://logging.apache.org/log4j/2.x/release-notes.html), and
[CISA KEV data](https://github.com/cisagov/kev-data).
