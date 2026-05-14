# PingCastle by Netwrix

## Stay Connected & Contribute

We welcome all PingCastle users: open source contributors, IT admins, and security professionals, to get involved and help shape the future of PingCastle.

- **Join the Netwrix Community**: [community.netwrix.com](https://community.netwrix.com)&nbsp;&nbsp;
Get announcements, view the roadmap, submit feature ideas, and connect with other users.
- **Contribute on GitHub** [github.com/netwrix/pingcastle](https://github.com/netwrix/pingcastle)
Submit pull requests, review open issues, or explore the codebase.&nbsp;

## Introduction

The threat landscape for Active Directory security continues to evolve at a rapid pace.
Well-known tools like [mimikatz](https://github.com/gentilkiwi/mimikatz) and resources such as [adsecurity.org](http://adsecurity.org/) have exposed and popularized numerous vulnerabilities that organizations must address.

PingCastle provides a streamlined approach to evaluating Active Directory security using a comprehensive risk assessment methodology and maturity framework.
Rather than pursuing exhaustive evaluation at the expense of efficiency, PingCastle delivers the optimal balance—identifying 80% of critical security issues while requiring just 20% of the time and effort of traditional assessment methods.

```plain
*****    #******** Netwrix PingCastle (Version 3.5.0.33)
 ***    %********** Get Active Directory Security at 80% in 20% of the time
 *      ####   #### End of support: 2027-08-31.
     ***#### ####
   *********   #### To find out more about PingCastle, visit <https://www.pingcastle.com>
 ####******%    ##  For online documentation, visit <https://helpcenter.netwrix.com/category/pingcastle>
####               For support and questions:
 ***********     ** -   Open-source community, visit <https://github.com/netwrix/pingcastle/issues>
 ***********   %*** -   Customers, visit <https://www.netwrix.com/support.html>
What do you want to do?
=======================
Using interactive mode.
Do not forget that there are other command line switches like --help that you can use
  1-healthcheck-Score the risk of a domain
  2-entraid    -Score the risk of Entra ID
  3-conso      -Aggregate multiple reports into a single one
  4-carto      -Build a map of all interconnected domains
  5-scanner    -Perform specific security checks on workstations
  6-export     -Export users or computers
  7-advanced   -Open the advanced menu
  0-Exit
==============================
This is the main functionality of PingCastle. In a matter of minutes, it produces a report which will give you an overview of your Active Directory security. This report can be generated on other domains by using the existing trust links.
```

Check <https://www.pingcastle.com> for the documentation and methodology

## Build

PingCastle is a C# project which can be built from Visual Studio 2012 to Visual Studio 2022.

## Features & Bugs

For reporting bugs or requesting features in the open source edition of PingCastle, we recommend using the [Netwrix Community](https://community.netwrix.com). Alternatively, you can submit an issue on GitHub.

Customers of a commercially available edition should contact [Netwrix technical support](https://www.netwrix.com/support.html).

Additionally, both open source users and customers can visit the [Netwrix Community](https://community.netwrix.com) to ask questions, suggest improvements, and stay updated on the latest developments.

## License

PingCastle is available under two licensing options:

1. **Open Source Edition**: Licensed under the Non-Profit Open Software License ("Non-Profit OSL") 3.0.
   - Organizations may use PingCastle internally without purchasing a license, even in for-profit companies.
   - This includes usage by a company's own IT staff or their contracted IT service providers.
   - You cannot monetize PingCastle or offer it as a paid service to others under this license.

2. **Commercial License**: Available for purchase.
   - Required for anyone who wants to incorporate PingCastle into commercial services or products.
   - Necessary if you plan to generate revenue by providing PingCastle-based services to other organizations.

In summary: Use it freely for internal purposes; purchase a license if you plan to make money from it.

PingCastle uses the following open source components:

* [Bootstrap](https://getbootstrap.com/) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [JQuery](https://jquery.org) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [vis.js](http://visjs.org/) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [popper.js](https://popper.js.org/) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [Bootstrap Table](https://bootstrap-table.com/) licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [Bootstrap Table Export](https://bootstrap-table.com) Licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [Table Export](https://github.com/hhurz/tableExport.jquery.plugin) Licensed under the [MIT license](https://tldrlegal.com/license/mit-license)
* [Font Awesome](https://fontawesome.com) Licensed under the [MIT license](https://tldrlegal.com/license/mit-license)

## Author

- General Contact: [PingCastle.Contact@netwrix.com](mailto:PingCastle.Contact@netwrix.com)
