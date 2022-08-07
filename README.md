# Ping Castle

## Introduction

The risk level regarding Active Directory security has changed.
Several vulnerabilities have been made popular with tools like [mimikatz](https://github.com/gentilkiwi/mimikatz) or sites likes [adsecurity.org](http://adsecurity.org/). 

Ping Castle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework.
It does not aim at a perfect evaluation but rather as an efficiency compromise.

```
  \==--O___      PingCastle (Version 2.11.0.0     07/08/2022 09:56:28)
   \  / \  ¨¨>   Get Active Directory Security at 80% in 20% of the time
    \/   \ ,'    End of support: 31/01/2024
     O¨---O
      \ ,'       Vincent LE TOUX (contact@pingcastle.com)
       v         twitter: @mysmartlogon       https://www.pingcastle.com
Using interactive mode.
Do not forget that there are other command line switches like --help that you can use
What you would like to do?
  1-healthcheck-Score the risk of a domain
  2-graph      -Analyze admin groups and delegations
  3-conso      -Aggregate multiple reports into a single one
  4-nullsession-Perform a specific security check
  5-carto      -Build a map of all interconnected domains
  6-scanner    -Perform specific security checks on workstations

```

Check https://www.pingcastle.com for the documentation and methodology

## Build

PingCastle is a c# project which can be build from Visual Studio 2012 to Visual Studio 2017

## Support & lifecycle

For support requests, you should contact support@pingcastle.com
The support for the basic edition is made on a best effort basis and fixes delivered when a new version is delivered.

The Basic Edition of PingCastle is released every 6 months (January, August) and this repository is updated at each release.

If you need changes, please contact contact@pingcastle.com for support packages.

## License

PingCastle source code is licensed under a proprietary license and the Non-Profit Open Software License ("Non-Profit OSL") 3.0.

Except if a license is purchased, you are not allowed to make any profit from this source code.
To be more specific:
* It is allowed to run PingCastle without purchasing any license on for profit companies if the company itself (or its ITSM provider) run it.
* To build services based on PingCastle AND earning money from that, you MUST purchase a license.

Ping Castle uses the following Open source components:

* [Bootstrap](https://getbootstrap.com/) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [JQuery](https://jquery.org) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [vis.js](http://visjs.org/) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)

## Author

Author: Vincent LE TOUX

You can contact me at vincent.letoux@gmail.com




