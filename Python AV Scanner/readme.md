
 Installation & Setup
1. Install Dependencies
pip install requests yara-python watchdog psutil
2. Set API Key
export VT_API_KEY="your_virustotal_api_key"
3. Run Scanner
python scanner.py scan /path/to/scan
4. Submit to VirusTotal
python scanner.py vt-file suspicious.exe
