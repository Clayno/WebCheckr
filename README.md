# WebCheckr
Initial check for web pentests.</br>

<h2>Installation</h2>
1 - First install docker and its python sdk</br>
Refer to docker documentation for the installation.</br>
</br>
For python:</br>
python3 -m pip install -r python3_dependencies</br>
</br>
2 - Pull required images:</br>
docker pull wpscanteam/wpscan</br>
docker pull wappalyzer/cli</br>
docker pull kodisha/gobuster</br>
docker pull pgrund/joomscan</br>
docker pull selenium/standalone-chrome</br>
docker pull ttimasdf/cve-search:withdb -- takes a lot of time...</br>
</br>
3 - Initiate docker image</br>
docker run -p 5000:5000 --name cvesearch ttimasdf/cve-search:withdb</br>
</br>
<h3>TODO</h3>
- Fix inconstistences in wappalyzer (puppeter ?) </br>
- Change user agent for all the requests</br>
- Fix dirb</br>
- Add header (cookies, server version) checks</br>
- Add SSL checks</br>
- Add Magescan or Magento</br>
- Handling of vhosts (or multiple technologies on one website such as multiple CMS). Currently, the scan doesn't launch</br>
- Database storage</br>
- Update cve-search docker automatically</br>
- Set timeout for check</br>
- Class for each modules (cve, foundings by wappalyzer) with to_string and to_html to make it more generic</br>
- Make an independent worker to give background actions to do (dirb, cms scanners)</br>
- Fully dockerize application = Docker network and stable wappalyzer + Selenium dockers
</br>
<h3>Functionality to add</h3>
- Default password checking (https://nmap.org/nsedoc/scripts/http-default-accounts.html)</br>
(https://github.com/NorthernSec/CVE-Scan)

