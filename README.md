# WebCheckr
Initial check for web pentests.</br>

<h2>Installation</h2>
1 - First install docker</br>
Refer to docker documentation for the installation.</br>
</br>
2 - Pull required images:</br>
docker pull wpscanteam/wpscan</br>
docker pull wappalyzer/cli</br>
docker pull kodisha/gobuster</br>
docker pull pgrund/joomscan</br>
docker pull selenium/standalone-chrome</br>
docker pull ttimasdf/cve-search:withdb -- takes a lot of time...</br>
</br>
3 - Initiate docker image and network</br>
docker network create webcheckr
docker create --net=webcheckr --name webcheckr_cvesearch ttimasdf/cve-search:withdb</br>
</br>
<h2>Run</h2>
```
docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock -v ${PWD}:/webcheckr --user $(id -u):$(id -g) --group-add $(stat -c '%g' /var/run/docker.sock) --net webcheckr webcheckr [OPTIONS]
```
</br>
It is advised to make an alias of this
<h3>TODO</h3>
- Fix inconstistences in wappalyzer (puppeter ?) 
- Change user agent for all the requests
- Fix dirb
- Add header (cookies, server version) checks
- Add SSL checks
- Add Magescan or Magento</br>
- Handling of vhosts (or multiple technologies on one website such as multiple CMS). Currently, the scan doesn't launch</br>
- Database storage</br>
- Update cve-search docker automatically</br>
- Set timeout for check
- Class for each modules (cve, foundings by wappalyzer) with to_string and to_html to make it more generic
- Make an independent worker to give background actions to do (dirb, cms scanners)
</br>
<h3>Functionality to add</h3>
- Default password checking (https://nmap.org/nsedoc/scripts/http-default-accounts.html)</br>
(https://github.com/NorthernSec/CVE-Scan)

