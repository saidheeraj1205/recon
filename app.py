from flask import Flask, render_template, request
import socket
import requests
import dns.resolver
import whois
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-ALT"
}


def clean_domain(target):
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.netloc
    return target.split("/")[0]


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Not Found"


def get_dns_records(domain):
    records = {}
    types = ["A", "AAAA", "MX", "NS", "TXT"]

    for record_type in types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]
        except:
            records[record_type] = ["Not Found"]

    return records


def get_whois_info(domain):
    try:
        data = whois.whois(domain)
        return {
            "domain_name": data.domain_name,
            "registrar": data.registrar,
            "creation_date": data.creation_date,
            "expiration_date": data.expiration_date,
            "name_servers": data.name_servers
        }
    except:
        return {
            "domain_name": "Not Found",
            "registrar": "Not Found",
            "creation_date": "Not Found",
            "expiration_date": "Not Found",
            "name_servers": "Not Found"
        }


def check_security_headers(domain):
    result = {
        "url": "",
        "status_code": "Not Reachable",
        "server": "Not Found",
        "headers": {}
    }

    urls = [f"https://{domain}", f"http://{domain}"]

    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            result["url"] = url
            result["status_code"] = response.status_code
            result["server"] = response.headers.get("Server", "Not Disclosed")

            for header in SECURITY_HEADERS:
                result["headers"][header] = "Present" if header in response.headers else "Missing"

            return result
        except:
            continue

    return result


def check_public_files(domain):
    files = {}
    for file_name in ["robots.txt", "sitemap.xml"]:
        url = f"https://{domain}/{file_name}"
        try:
            response = requests.get(url, timeout=5)
            files[file_name] = "Found" if response.status_code == 200 else "Not Found"
        except:
            files[file_name] = "Not Found"

    return files


def check_ports(ip):
    port_results = []

    if ip == "Not Found":
        return port_results

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            status = sock.connect_ex((ip, port))
            sock.close()

            port_results.append({
                "port": port,
                "service": service,
                "status": "Open" if status == 0 else "Closed"
            })
        except:
            port_results.append({
                "port": port,
                "service": service,
                "status": "Error"
            })

    return port_results


def calculate_risk(headers, ports):
    score = 0

    for value in headers["headers"].values():
        if value == "Missing":
            score += 10

    for port in ports:
        if port["status"] == "Open":
            score += 5

    if score > 100:
        score = 100

    if score <= 30:
        level = "Low"
    elif score <= 60:
        level = "Medium"
    else:
        level = "High"

    return score, level


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        permission = request.form.get("permission")
        target = request.form.get("domain")

        if permission != "yes":
            error = "You must confirm that you have permission to scan this target."
        elif not target:
            error = "Please enter a domain."
        else:
            domain = clean_domain(target)
            ip = get_ip(domain)
            dns_records = get_dns_records(domain)
            whois_info = get_whois_info(domain)
            security_headers = check_security_headers(domain)
            public_files = check_public_files(domain)
            ports = check_ports(ip)
            risk_score, risk_level = calculate_risk(security_headers, ports)

            result = {
                "domain": domain,
                "ip": ip,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "dns": dns_records,
                "whois": whois_info,
                "security": security_headers,
                "files": public_files,
                "ports": ports,
                "risk_score": risk_score,
                "risk_level": risk_level
            }

    return render_template("index.html", result=result, error=error)


if __name__ == "__main__":
    app.run(debug=True)