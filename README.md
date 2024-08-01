# PingCastle by Netwrix

## Acquisition Announcement

We are excited to announce that PingCastle has been acquired by [Netwrix](http://www.netwrix.com/)!

Netwrix understands that commercial acquisitions of open source solutions can create concerns within the community. We are committed to actively stewarding the project and maintaining the availability of the open source edition.

PingCastle has a long history of offering both open source and commercial editions. Netwrix is not only committed to preserving the open source project but also increasing development resources to enhance both the open source and commercial versions with new features and capabilities.

Netwrix, an industry leader in Active Directory security solutions and other cybersecurity solutions, ensures a brighter digital future for more than 13,500 customers worldwide. Netwrix empowers security professionals to face digital threats with confidence by enabling them to identify and protect sensitive data as well as to detect, respond to, and recover from attacks.

## Introduction

The risk level regarding Active Directory security has changed.
Several vulnerabilities have been made popular with tools like [mimikatz](https://github.com/gentilkiwi/mimikatz) or sites likes [adsecurity.org](http://adsecurity.org/).

PingCastle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework.
It does not aim at a perfect evaluation but rather as an efficiency compromise.

```plain
  \==--O___      PingCastle (Version 3.1.0.0     8/03/2023 7:25:24 PM)
   \  / \  "">   Get Active Directory Security at 80% in 20% of the time
    \/   \ ,'    End of support: 7/31/2024
     O"---O
      \ ,'       PingCastle.Contact@netwrix.com
       v         https://www.pingcastle.com
What do you want to do?
=======================
Using interactive mode.
Do not forget that there are other command line switches like --help that you can use
  1-healthcheck-Score the risk of a domain
  2-azuread    -Score the risk of AzureAD
  3-conso      -Aggregate multiple reports into a single one
  4-carto      -Build a map of all interconnected domains
  5-scanner    -Perform specific security checks on workstations
  6-export     -Export users or computers
  7-advanced   -Open the advanced menu
  0-Exit
==============================
This is the main functionnality of PingCastle. In a matter of minutes, it produces a report which will give you an overview of your Active Directory security. This report can be generated on other domains by using the existing trust links.
```

Check <https://www.pingcastle.com> for the documentation and methodology

## Build

PingCastle is a c# project which can be build from Visual Studio 2012 to Visual Studio 2022

## Features & Bugs

For reporting bugs or requesting features in the open source edition of PingCastle, please create a Github issue.

Customers of a commercially available edition should contact [Netwrix technical support](https://www.netwrix.com/support.html).

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
* [popper.js](https://popper.js.org/) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [Bootstrap Table](https://bootstrap-table.com/) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)

## Author

*	General Contact: [PingCastle.Contact@netwrix.com](mailto:PingCastle.Contact@netwrix.com)
