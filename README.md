# 🔍 Automated Information Gathering (IG) Tool  

## **📌 Overview**
The **Automated IG Tool** is a **CLI-based reconnaissance tool** designed for **ethical hacking, OSINT (Open Source Intelligence), and penetration testing**.  
It helps security professionals collect **publicly available data** about a target domain.

---

## **📦 Features**
**robots.txt & Sitemap Extraction** – Identifies restricted and indexed paths.  
**WHOIS Lookup** – Retrieves domain ownership and registrar information.  
**IP Geolocation** – Finds server location, ISP, and network details.  
**Port Scanning** – Identifies open ports and associated services.  
**Google Dorking** – Automates advanced Google searches for sensitive data.  
**Metadata Extraction** – Extracts hidden metadata from web pages.  

---

Automated_IG_Tool/  
│── README.md                # Project Documentation  
│── requirements.txt         # Dependencies List  
│── Automated_IG_Tool.py     # Main Python Script (All Features)  
│── results/                 # Stores scanned results  
│   ├── info_gathering_results.json  # JSON output file 

## **🛠 Installation**
### **1️⃣ Install Dependencies**
```bash
pip install -r requirements.txt
```

### **2️⃣ Run the Tool**
```bash
python Automated_IG_Tool.py
```

---

## **🖥️ Usage**
1️⃣ **Enter the target domain**  
2️⃣ **Select which features to enable** (Yes/No options)  
3️⃣ **Results are displayed and saved in `info_gathering_results.json`**  

**Example Run:**
```
Enter target domain: example.com
Enable/Disable Features:
1. robots.txt Extraction (y/n)? y
2. WHOIS Lookup (y/n)? y
3. IP Geolocation (y/n)? y
4. Port Scanning (y/n)? n
...
✔✔ Results saved to info_gathering_results.json
```

---

## **📂 Output Format**
The results are saved in a structured **JSON file**:
```json
{
    "WHOIS Lookup": {
        "Domain Name": "example.com",
        "Registrar": "GoDaddy.com, LLC",
        "Creation Date": "2010-05-12",
        "Expiration Date": "2025-05-12"
    },
    "IP Geolocation": {
        "IP": "93.184.216.34",
        "Country": "United States",
        "City": "Los Angeles",
        "ISP": "Edgecast"
    }
}
```

---

## **🔮 Future Improvements**  

🔹 **Splitting Features into Modules** – We will organize each feature into separate files for better code structure and easy understanding.  

🔹 **Integration with OSINT APIs** – Improve results by integrating APIs like Shodan, Have I Been Pwned, and Censys.  

🔹 **Enhanced Google Dorking** – Automate advanced Google searches to retrieve more sensitive information.  

🔹 **Advanced Port Scanning** – Improve port scanning by adding banner grabbing and vulnerability detection.  

🔹 **Automated Reporting** – Generate detailed PDF/HTML reports with findings and analysis.  

---

## **⚠️ Legal Disclaimer**
🚨 **This tool is intended for educational & ethical hacking purposes only.**  
Unauthorized use against **any website or network without permission** is illegal and punishable by law.  

---

## License
This project is licensed under the [MIT License](LICENSE).
