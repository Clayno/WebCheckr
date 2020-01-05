# Template of report
report = '''<!DOCTYPE html>
<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<head>
<style>
body{{
    font-family: "Arial";
}}

h2{{
    color: black;
}}

.content{{
    position: static;
    overflow: hidden;
    border: 1px solid rgb(204, 204, 204);
    border-radius: 5px;
    padding: 0.01em 16px;
}}

.screenshot{{
    position: static;
    float: right;
    max-width:30%;
    max-height:30%;
}}

table {{
  border-collapse: collapse;
}}
th, td {{
  border-bottom: 1px solid #ddd;
}}

tr:hover {{background-color: #f5f5f5;}}

</style>
<title>WebCheckr Report</title>
</head>
<body>

{0}

</body>
<script>
function togglediv(id) {{
    var div = document.getElementById(id);
    div.style.display = div.style.display == "none" ? "block" : "none";
    }}
</script>
</html>'''


def write_html(base_dir, checks):
    final = ""
    i = 0
    for check in checks:
        modules_html = ""
        for module in check.modules:
            modules_html += module['visual']['html']
        if check is None:
            final += ''
        else:
            final += '''<div class="check">
        <div class="check-title">
            <h2>{url} ({title})</h2>
            <button onclick="togglediv('content{id}')">toggle</button>
        </div>
        <div class="content" id="content{id}">
            <img class="screenshot" src="data:image/png;base64, {screen}">
            <p>
            <b>Directory:</b> {directory}</br>
            </p>
            {modules}
            <p class="cve">
            <b>CVE found:</b></br>
                {cve}</br>
            </p>
        </div>
    </div>
    </br>
    '''.format(url=check.hostname, directory=check.directory, screen=check.screen_content,
                    modules=modules_html, cve=cve_to_html(check.cve), id=str(i), title=check.title)
        i += 1
    with open(f"{base_dir}/report.html", 'w') as f:
        f.write(report.format(final))
    return final
        
def cve_to_html(cve):
    '''
    Templates cve found in html.
    '''
    if not cve:
        return "Nothing found"
    final = "<table>\n"
    final += '<th>Technology</th><th>Nb vulns</th><th>Nb critical</th>\n'
    for vuln in cve.values(): 
        final += '<tr><td>{name}:{version}</td><td>{number_cve}</td><td>{number_critical_cve}</td></tr>\n'.format(name=vuln['name'], version=vuln['version'], number_cve=vuln['number_cve'], number_critical_cve=vuln['number_critical_cve'])
    final += "</table>\n"
    return final

def credscheckr_to_html(result):
    final = ""
    final += "<b>CredsCheckr</b></br>"
    if result['scheme'] == 'basic_auth':
        final += "Basic auth protected page</br>"
    elif result['scheme'] == 'form':
        final += "Form login page</br>"
    else:
        final += "Not an authentication page</br>"
    if result['creds'] is not None:
        final += "Creds found: "
        final += "<table>\n"
        final += '<th>Username</th><th>Password</th>\n'
        for cred in result['creds']:
            final += f'<tr><td>{cred["username"]}</td><td>{cred["password"]}</td></tr>\n'
        final += "</table>\n"
    return final
