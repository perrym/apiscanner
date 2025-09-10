# Ultimate Swagger Generator, find hidden api's  1.0

**Ultimate Swagger Generator** is an advanced API documentation crawler and generator, designed to automatically discover RESTful APIs, WebSockets, GraphQL endpoints, and other services from a target website or API server.

It intelligently crawls, inspects responses, follows links, parses JavaScript files, and analyzes HTML forms to reconstruct a complete OpenAPI (Swagger 3.0) specification file.

---

##  **New version and Features**

- New version with beter checks 
- Delay scan 
- Deep recursive crawling with intelligent endpoint detection
- Aggressive mode for brute-forcing common API endpoints
- Supports Basic Authentication, Bearer Tokens, and Form-Based Login
- Automatic detection of:
- REST endpoints
- WebSocket URLs
- GraphQL endpoints
- HATEOAS-style hypermedia links
- Automatically builds OpenAPI 3.0 specifications
-️ Custom headers support for accessing protected APIs
- JavaScript parsing to discover hidden APIs
- Beautiful JSON output with optional WebSocket server listings
- CLI interface with flexible authentication and crawling options

---

## Usage Example

```
python swagger_generatov.py --url https://target-api.com --output swagger.json --depth 3 --aggressive
```

Optional parameters:
- `--username` and `--password` for Basic Auth
- `--token` for Bearer Token authentication
- `--login-url` and `--login-data` for form-based authentication
- `--header` for custom headers (`Header-Name:Value` format)

---

## Disclaimer

This tool is intended for **educational and authorized security testing purposes only**.  
Unauthorized use against systems without proper consent is strictly prohibited.

Always ensure you have permission before scanning, crawling, or testing any target systems.

---

## Contact

For questions, improvements, or responsible disclosure, please contact:  
 **pamsniffer@gmail.com**

---

## Bonus Tip
You can combine Ultimate Swagger Generator with tools like **Postman**, **Swagger Editor**, or **APISCAN** for extended testing and automation.
