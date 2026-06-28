# CORS Misconfiguration Tester

A Python scanner designed to evaluate API endpoints for CORS misconfigurations and credentials reflection bugs.

## 📋 Features

- **Origin Reflection Check**: Audits whether endpoints dynamically reflect the `Origin` header.
- **Null Origin Check**: Verifies if `Origin: null` is trusted.
- **Dynamic Origin with Credentials**: Analyzes whether `Access-Control-Allow-Credentials: true` is shared with dynamically reflected origins.
- **Subdomain Validation Check**: Audits if trusted domain regex checks can be bypassed using subdomain combinations.

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/amooryx/cors-tester.git
   cd cors-tester
   ```

2. Install dependencies:
   ```bash
   pip install requests
   ```

## 🚀 Usage

Scan an endpoint for CORS configurations:

```bash
python main.py -u https://api.target.com/v1/data
```

## 🛡️ Disclaimer

This tool is designed for educational and security compliance auditing purposes only. Ensure you have authorized permission prior to running scans against active environments.
