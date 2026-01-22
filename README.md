🛡️ Phishing URL Detector (Python)

# phishing-url-detector
A Python-based phishing URL detection tool that flags suspicious links using heuristic analysis. Built for cybersecurity beginners and SOC/Blue Team learning.
A beginner-friendly cybersecurity project that detects potentially phishing or malicious URLs using heuristic analysis.
Built for students and aspiring SOC / Blue Team / Purple Team roles.

🚀 Features
Detects suspicious URL patterns
Flags IP-based, misleading, and risky URLs
Simple CLI-based interface
Great for learning Web Security & Threat Detection basics

🧠 How It Works
The tool analyzes a given URL and checks for:
Use of IP address instead of domain
Suspicious keywords (login, verify, update, etc.)
Abnormal length or structure
HTTP instead of HTTPS
Based on these checks, it reports whether the URL looks Safe or Suspicious.

🛠️ Setup & Run (VS Code / Terminal)
Clone the repo:
git clone https://github.com/your-username/phishing-url-detector.git
cd phishing-url-detector

Run the program:
python detector.py
Enter a URL when prompted:
Enter a URL: http://192.168.0.1/login/update

📁 Project Structure
phishing-url-detector/
│
├── detector.py
└── README.md

🎯 Learning Outcomes
Understand phishing URL indicators
Practice Python for security automation
Learn basic threat detection logic
Prepare for SOC / Cybersecurity interviews

📌 Disclaimer
This tool is for educational purposes only.
It does not replace professional security tools.

👩‍💻 Author
Shravani Shinde
Cybersecurity & AI/DS Student | Aspiring Purple Team Engineer
