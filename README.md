# CTI-Search-Criminalip-Search-Tool
The CTI Search Engine tool, Asset Search, Domain Search, allows you to extract CVE code values and Explicit Code values


Criminalip Search

  - [IP Asset Search](https://www.criminalip.io/developer/api/get-ip-data)
  - Data: VPN, Proxy, Cloud, Tor, Webcam Leak Information URL/Country/City/Open Port/manufacturer, Banner, CVE Information, ASN, Protocol, Product, Product Version, Vendor
    
    !Tip : Although it has not yet been implemented in the criminalip, the CVE value allows you to find the value of the Explicit Code using the API that someone has published on github.
    
    ex: https://poc-in-github.motikan2010.net/api/v1/?cve_id=CVE-2022-0847
    
    API Executable: https://poc-in-github.motikan2010.net/api/v1/?cve_id={CVE_Information}
    
  - [Domain Search](https://www.criminalip.io/developer/api/get-domain-report-id)
  - Data: protocol, Subject, Domain, ASN, EXE Program information, DNS Information(MX), Page redirections, Screenshots, Subdomains, CVE Information 

    !Tip : If a domain is alive, a report is generated for that domain, and it tells you about the CVE value and the SubDomain associated with it.
    For more information, please refer to the official website of Criminalip.

    ex: https://poc-in-github.motikan2010.net/api/v1/?cve_id=CVE-2022-0847
    
    API Executable: https://poc-in-github.motikan2010.net/api/v1/?cve_id={CVE_Information}
    
    _**Domain Search Report Generator Logic**_
    
![image](https://user-images.githubusercontent.com/15859838/209637233-01fc9aa9-ede7-488a-86ce-9872c536f097.png)
