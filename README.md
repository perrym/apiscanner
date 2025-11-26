# APISCAN OWASP APIscanner by Perry Mertens pamsniffer@gmail.com 2025 (c)
<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">

**Author:** Perry Mertens ([pamsniffer@gmail.com](mailto:pamsniffer@gmail.com))  
**Year:** © 2025 Perry Mertens  
**Version:** 3.0 (Release)  
**License:** GNU Affero General Public License v3.0 (AGPL-v3.0)

APIscan is an API vulnerability scanner that proactively identifies security risks by testing against the OWASP API Security Top 10 (2023).
It uses your OpenAPI/Swagger specification to generate realistic attack payloads and detect issues such as Broken Object Level Authorization (BOLA),
Broken Authentication, Excessive Data Exposure, and other critical API vulnerabilities.
It understands **OpenAPI/Swagger**, supports **multiple authentication flows**, provides a **plan/verify workflow**, includes a **generic sanitizer/rewrites**, and writes **CSV/HTML** artifacts.

![APISCAN v3.0 dashboard](./apiscan_v3_dashboard.jpg)

---

## License

APISCAN is licensed under the **AGPL-3.0**.

---

## What’s new in v3.0

- Generic sanitizer  
- Universal header overrides  
- ID & sample generation  
- Improved planning  
- Enhanced verification  
- Adaptive retry  

---

## Core features

- OWASP API Top 10 coverage  
- OpenAPI/Swagger-based  
- Multi-auth support  
- Plan/Verify workflow  
- CSV & HTML output  
- Proxy support  
- AI-assisted analysis  

---

## Install

```bash
python -m venv .venv
source .venv/bin/activate     # Linux/macOS
# .venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

---

## Quick start

```bash
python apiscan.py --url https://api.example.com   --swagger openapi.json   --flow token --token "<BEARER>"   --verify-plan
```

---

## Contact

pamsniffer@gmail.com
