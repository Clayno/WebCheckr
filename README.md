# WebCheckr
Initial check for web pentests.</br>

<h2>Installation</h2>
1 - First install docker</br>
Refer to docker documentation for the installation.</br>
</br>
2 - Pull required images:</br>

```
docker pull wpscanteam/wpscan
docker pull wappalyzer/cli
docker pull kodisha/gobuster
docker pull pgrund/joomscan
docker pull selenium/standalone-chrome
docker pull ttimasdf/cve-search:withdb -- takes a lot of time...
```

3 - Initiate docker image and network</br>

```
docker network create webcheckr
docker create --net=webcheckr --name cvesearch_docker ttimasdf/cve-search:withdb
```
OR

run startup.sh, sudo is required during install

```
./startup.sh
```

<h2>Run</h2>

```
docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock -v ${PWD}:/webcheckr/shared --user $(id -u):$(id -g) --group-add $(stat -c '%g' /var/run/docker.sock) --net webcheckr webcheckr [OPTIONS]
```

OR if setup was used

```
webcheckr [OPTIONS]
```

</br>
It is advised to make an alias of this
<h3>TODO</h3>
- Add common.txt discovery and launch tests on found URLs
- Change user agent for all the requests</br>
- Add header (cookies, server version) checks</br>
- Add SSL checks</br>
- Add Magescan or Magento</br>
- Handling of vhosts (or multiple technologies on one website such as multiple CMS). Currently, the scan doesn't launch</br>
- Database storage</br>
- Update cve-search docker automatically</br>
- Class for each modules (cve, foundings by wappalyzer) with to_string and to_html to make it more generic</br>
- Make an independent worker to give background actions to do (cms scanners)
</br>
<h3>Functionality to add</h3>
- Default password checking (https://nmap.org/nsedoc/scripts/http-default-accounts.html)</br>
(https://github.com/NorthernSec/CVE-Scan) (CredsCheckr :))

