# APISCAN.py 0.1.0-alpha - (REST) API Security Assessment Tool (by Perry Mertens)

APISCAN is an extensible, modular security auditing framework for REST APIs, based on the OWASP API Security Top 10 (2023) risks.

1. Summary
APISCAN is an extensible and modular Python-based security scanner for REST APIs. 
It automates the detection of vulnerabilities based on the OWASP API Security Top 10 (2023) standard. 
APISCAN parses OpenAPI/Swagger specifications, runs active tests against API endpoints, and produces clear reports in Markdown, JSON, and CSV formats. It focuses on realistic attack simulation techniques, evidence-based findings, and extensibility for future expansion.

2. OWASP API Security Top 10 Coverage
OWASP API Risk	APISCAN.PY Coverage	Module

| OWASP API Risk | APISCAN Coverage | Module |
|:--|:--|:--|
| API1: Broken Object Level Authorization | Access control bypass via object ID manipulation | `bola_audit.py` |
| API2: Broken Authentication | Weak login protections, session handling flaws, token misuse | `broken_auth_audit.py` |
| API3: Broken Object Property Level Authorization | Mass assignment, unauthorized property manipulation | `broken_object_property_audit.py` |
| API4: Unrestricted Resource Consumption | Abuse of API endpoints through large/batch requests | `resource_consumption_audit.py` |
| API5: Broken Function Level Authorization | Partial coverage via role misuse checks | `authorization_audit.py` *(partial)* |
| API6: Mass Assignment | Partially tested through property injection | `broken_object_property_audit.py` |
| API7: Security Misconfiguration | Missing security headers, server misconfiguration detection | `misconfiguration_audit.py` |
| API8: Injection | Partially tested via authentication and external API tests | `broken_auth_audit.py`, `safe_consumption_audit.py` |
| API9: Improper Inventory Management | Exposed API documentation and debug endpoints | `inventory_audit.py` |
| API10: Unsafe Consumption of 3rd-Party APIs | Injection and SSRF risks through external APIs | `safe_consumption_audit.py` |


3. Module Descriptions
Each APISCAN module targets specific OWASP API risks with realistic attack simulations. The tests include fuzzing, timing analysis, authorization bypass attempts, response reflection analysis, security header evaluation, and concurrency stress tests.

4. Conclusion and Future Enhancements
APISCAN currently provides strong coverage for the most critical API security risks. Future enhancements could include more in-depth Injection testing (SQL, SSTI), advanced function-level authorization validation, and fuzzing based on OpenAPI schemas.

APISCAN supports OpenAPI/Swagger specification parsing, advanced payload generation, concurrent testing, and evidence-based reporting.

## Features
- Modular structure per OWASP risk category
- Realistic attack simulation (fuzzing, timing attacks, header tampering)
- Clear Markdown, JSON, and txten docx output formats
- Designed for both developers and security auditors

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Disclaimer
This tool is intended for educational and authorized security testing purposes only. Unauthorized use against systems without permission is prohibited.

## Contact
For any questions, feedback, or responsible disclosure, please contact: pamsniffer@gmail.com

Note *** some code is stiil in Dutch, this wil change in 2 changes ****



