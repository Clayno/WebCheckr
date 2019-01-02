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
- HTTP/HTTPS handling, for the cases when the urls are not provided with the right protocol and the site is poorly configured.</br>
- Handling of vhosts (or multiple technologies on one website such as multiple CMS). Currently, the scan doesn't launch</br>
- Colorize output</br>
- Database storage</br>
- Update cve-search docker automatically</br>
- Create HTML output</br>
- Better handling of running containers as a list and not unitary work to parallelize</br> 
</br>
<h3>Functionality to add</h3>
- Default password checking (https://nmap.org/nsedoc/scripts/http-default-accounts.html)</br>
(https://github.com/NorthernSec/CVE-Scan)
