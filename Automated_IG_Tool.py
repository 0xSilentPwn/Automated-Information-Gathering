import whois
import requests
import json
import socket
import threading
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

def fetch_robots_txt(domain):
    # Ensure the URL starts with 'http://' or 'https://'
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain

    robots_url = domain.rstrip('/') + '/robots.txt'

    try:
        response = requests.get(robots_url)
        if response.status_code == 200:
            return response.text  # Returns the content of robots.txt
        else:
            return f"robots.txt not found or inaccessible. Status code: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error occurred: {e}"
    
def extract_sitemap_urls(domain):
    """Fetch and parse sitemap.xml with error handling & headers."""
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain
    
    sitemap_url = domain.rstrip('/') + '/sitemap.xml'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(sitemap_url, headers=headers, timeout=25)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            return [elem.text for elem in root.iter() if elem.tag.endswith("loc")]
        elif response.status_code == 403:
            return {"error": "Access Forbidden"}
        else:
            return {"error": f"Failed to fetch sitemap: {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out. Try increasing timeout or using a proxy."}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}

def whois_lookup(domain):
    try:
        info = whois.whois(domain)
        return {
            "Domain Name": info.domain_name,
            "Registrar": info.registrar,
            "Creation Date": str(info.creation_date),
            "Expiration Date": str(info.expiration_date),
            "Name Servers": info.name_servers,
        }
    except Exception as e:
        return {"Error": str(e)}

def get_ip_info(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url).json()
        return {
            "IP": response.get("query"),
            "Country": response.get("country"),
            "City": response.get("city"),
            "ISP": response.get("isp"),
            "Lat": response.get("lat"),
            "Lon": response.get("lon"),
            "Timezone": response.get("timezone")
        }
    except:
        return {"Error": "Failed to retrieve IP details"}
    
def google_dorking(domain):
    queries = {
        "Sensitive Files": f"site:{domain} ext:log OR ext:txt OR ext:conf",
        "Exposed Admin Panels": f"site:{domain} inurl:admin",
        "Open Indexes": f"site:{domain} intitle:index.of"
    }
    return queries

# Multi-threaded Port Scanner

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    465: "SMTPS", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 135: "MSRPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    4444: "Metasploit", 5555: "ADB", 6667: "IRC"
}

def scan_port(target, port, open_ports):
    """Scans a single port and stores open ones with their service name."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))

    if result == 0:
        service = PORT_SERVICES.get(port, "Unknown Service")  # Get service name or mark as unknown
        open_ports.append(f"{port} ({service})")
    
    sock.close()

def scan_ports(target, ports=None):
    """Scans specified ports and returns open ones with service names."""
    if ports is None:
        ports = list(PORT_SERVICES.keys())  # Default to scanning known ports

    open_ports = []
    threads = []

    for port in ports:
        thread = threading.Thread(target=scan_port, args=(target, port, open_ports))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return open_ports

def extract_metadata(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain
    
    metadata_url = domain.rstrip('/')

    try:
        response = requests.get(metadata_url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        metadata = {}

        # Extract metadata
        for meta in soup.find_all('meta'):
            if 'name' in meta.attrs and 'content' in meta.attrs:
                metadata[meta.attrs['name']] = meta.attrs['content']
            if 'property' in meta.attrs and 'content' in meta.attrs:
                metadata[meta.attrs['property']] = meta.attrs['content']

        return metadata
    except requests.exceptions.RequestException as e:
        return {'Error': f"Unable to fetch website metadata ({e})"}


def main():
    domain = input("Enter target domain: ")

    options = {
        "Robot txt ": fetch_robots_txt,
        "Sitemap xml": extract_sitemap_urls,
        "WHOIS Lookup": whois_lookup,
        "IP Geolocation": lambda d: get_ip_info(socket.gethostbyname(d)),
        "Port Scanning": scan_ports,
        "Google Dorking": google_dorking,
        "Metadata Extraction": extract_metadata
    }
    enabled_features = {}
    print("\nEnable/Disable Features:")
    for idx, feature in enumerate(options.keys(), 1):
        choice = input(f"{idx}. {feature} (y/n)? ").strip().lower()
        if choice == 'y':
            enabled_features[feature] = options[feature]

    results = {}
    for feature, func in enabled_features.items():
        print(f"\n[+] Running {feature}...")
        results[feature] = func(domain)

    # Convert sets to lists in the results
    for key, value in results.items():
        if isinstance(value, set):
            results[key] = list(value)

    # Save to JSON File
    with open("Results\info_gathering_results.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\n✔✔ Results saved to info_gathering_results.json")

# Run the script
if __name__ == "__main__":
    main()