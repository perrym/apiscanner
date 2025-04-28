# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
from docx import Document
from docx.shared import Pt, Inches
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
import json
import re
from pathlib import Path
from datetime import datetime



# Risk descriptions and recommendations (OWASP API Top 10 2023)
# Risk descriptions and recommendations (OWASP API Top 10 – 2023)
RISK_INFO = {
    "BOLA": {
        "title": "API1:2023 – Broken Object Level Authorization",
        "description": (
            "APIs exposen object-ID’s in hun endpoints. Aanvallers kunnen door ID’s te "
            "manipuleren ongeautoriseerde data ophalen of wijzigen."
        ),
        "recommendation": """- Implementeer object-niveau autorisatiechecks op elke request
- Gebruik onvoorspelbare ID’s (UUID) in plaats van oplopende integers
- Controleer of de aanvrager eigenaar/toegangsrechten heeft voor elk object
- Centraliseer autorisatielogica
- Log en alarmeer op mislukte autorisatiepogingen"""
    },
    "BrokenAuth": {
        "title": "API2:2023 – Broken Authentication",
        "description": (
            "Onjuiste implementaties van authenticatie maken het mogelijk om tokens te stelen "
            "of sessies over te nemen."
        ),
        "recommendation": """- Gebruik MFA voor gevoelige acties
- Werk met kort-levende, cryptografisch ondertekende tokens
- Beveilig flows voor wachtwoord-/token-herstel
- Lock accounts tijdelijk na te veel mislukte pogingen
- Exporteer nooit credentials in URLs of foutmeldingen"""
    },
    "Property": {
        "title": "API3:2023 – Broken Object Property Level Authorization",
        "description": (
            "Mass assignment en over-exposure: clients kunnen velden zien of aanpassen die "
            "eigenlijk verborgen moeten blijven."
        ),
        "recommendation": """- Definieer expliciet welke velden per rol zichtbaar/wijzigbaar zijn
- Valideer request- en response-payloads met schemas
- Filter gevoelige velden server-side vóór verzending
- Gebruik verschillende DTO’s voor verschillende toegangsniveaus
- Splits publieke en privé-eigenschappen strikt"""
    },
    "Resource": {
        "title": "API4:2023 – Unrestricted Resource Consumption",
        "description": (
            "Geen limieten op payload-grootte, paginering of requests kan leiden tot DoS of "
            "hogere kosten door resource-uitputting."
        ),
        "recommendation": """- Implementeer rate limiting en quota’s
- Stel maximale payload-groottes in
- Gebruik paginering of partial responses
- Monitor afwijkend verbruik
- Cache dure operaties waar mogelijk"""
    },
    "AdminAccess": {
        "title": "API5:2023 – Broken Function Level Authorization",
        "description": (
            "Complexe rol-/functie-matrix leidt vaak tot endpoints die voor gewone gebruikers "
            "toegankelijk zijn terwijl ze alleen voor admins bedoeld zijn."
        ),
        "recommendation": """- Gebruik RBAC of ABAC met deny-by-default
- Centraliseer autorisatielogica
- Test ALLE admin-functies uitgebreid
- Verplicht step-up-authenticatie voor kritieke acties
- Documenteer en versleutel gevoelige admin-flows"""
    },
    "BusinessFlows": {
        "title": "API6:2023 – Unrestricted Access to Sensitive Business Flows",
        "description": (
            "Aanvallers kunnen gevoelige business-processen (bijv. checkout, booking) "
            "automatiseren of misbruiken als er geen anti-fraude-maatregelen zijn."
        ),
        "recommendation": """- Voeg business-context-validaties toe (bijv. saldo, limieten)
- Gebruik CAPTCHA/rate limiting tegen bots
- Detecteer en blokkeer afwijkende patronen
- Vereis step-up-authenticatie bij risicovolle acties
- Monitor kritieke flows realtime"""
    },
    "SSRF": {
        "title": "API7:2023 – Server Side Request Forgery",
        "description": (
            "APIs die externe URL’s ophalen kunnen misbruikt worden om interne diensten te "
            "benaderen of metadata te lekken."
        ),
        "recommendation": """- Valideer & sanitiseer alle aangeleverde URL’s
- Gebruik een allow-list van toegestane domeinen
- Volg geen redirects of beperk het aantal hops
- Segmenter interne netwerken; blokkeer uitgaande requests waar mogelijk
- Pas egress-firewallregels toe"""
    },
    "Misconfig": {
        "title": "API8:2023 – Security Misconfiguration",
        "description": (
            "Standaard- of foutieve configuraties (CORS, headers, debug-modi) kunnen gevoelige "
            "informatie lekken of aanvallen vergemakkelijken."
        ),
        "recommendation": """- Harden systemen volgens security-baselines
- Schakel onnodige HTTP-methoden uit
- Verwijder debug-/test-endpoints in productie
- Stel strikte CORS-policies in
- Review & patch configuraties regelmatig"""
    },
    "Inventory": {
        "title": "API9:2023 – Improper Inventory Management",
        "description": (
            "Onvolledig overzicht van endpoints/versies leidt tot shadow-API’s en oude, "
            "ongepatchte versies online."
        ),
        "recommendation": """- Onderhoud een actuele inventaris van alle endpoints
- Deprecate & verwijder oude versies zorgvuldig
- Documenteer elke endpoint met doel & eigenaar
- Implementeer duidelijke versioning-strategie
- Scan proactief op niet-gedocumenteerde API’s"""
    },
    "UnsafeConsumption": {
        "title": "API10:2023 – Unsafe Consumption of APIs",
        "description": (
            "Te veel vertrouwen op data van derden kan leiden tot injecties of afwijkend gedrag "
            "als de externe API zich onverwacht gedraagt."
        ),
        "recommendation": """- Valideer & saniteer alle data van third-party API’s
- Stel tijdslimieten & retries in
- Faal veilig: handel externe fouten gracieus af
- Houd third-party credentials geheim & rotatie geregeld
- Monitor het gedrag van externe diensten continu"""
    }
}



def create_audit_report(output_dir: Path):
    """Create comprehensive DOCX report from all scan results"""
    doc = Document()
    
    # Add title page
    doc.add_heading('API Security Audit Report. This program is created by Perry Mertens April 2025 (c)', 0)
    doc.add_paragraph('Generated on: ' + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    doc.add_page_break()
    
    # Table of Contents
    doc.add_heading('Table of Contents', 1)
    paragraphs = []
    for risk in RISK_INFO.values():
        paragraphs.append(risk["title"])
    doc.add_paragraph('\n'.join(paragraphs))
    doc.add_page_break()

    # Special mapping for shorter filenames
    manual_file_map = {
        'BOLA': 'bola',
        'BrokenAuth': 'broken_auth',
        'UnsafeConsumption': 'safe_consumption', 
        # Voeg hier nieuwe mappings toe als je nieuwe risico's scant
    }

    # Add content for each risk
    for risk_name, info in RISK_INFO.items():
        doc.add_heading(info["title"], level=1)

        doc.add_heading('Description', level=2)
        doc.add_paragraph(info["description"])

        doc.add_heading('Findings', level=2)
        snake = manual_file_map.get(risk_name, re.sub(r'(?<!^)(?=[A-Z])', '_', risk_name).lower())
        report_file = output_dir / f"api_{snake}_report.txt"
        if report_file.exists():
            findings = report_file.read_text(encoding='utf-8')
            clean_findings = ''.join(c for c in findings if c.isprintable() or c in '\n\r\t')
            doc.add_paragraph(clean_findings)
        else:
            doc.add_paragraph("No findings reported for this risk")

        doc.add_heading('Recommendations', level=2)
        doc.add_paragraph(info["recommendation"])

        doc.add_page_break()

    # Add summary
    doc.add_heading('Executive Summary', level=1)
    summary_file = output_dir / "api_summary_report.txt"
    if summary_file.exists():
        summary = json.loads(summary_file.read_text(encoding='utf-8'))
        table = doc.add_table(rows=1, cols=3)
        table.style = 'Light Shading Accent 1' 
        
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = 'Risk'
        hdr_cells[1].text = 'OWASP Category'
        hdr_cells[2].text = 'Vulnerabilities Found'

        for risk, count in summary.items():
            row_cells = table.add_row().cells
            row_cells[0].text = risk
            row_cells[1].text = RISK_INFO.get(risk, {}).get("title", "N/A")
            row_cells[2].text = str(count)

    report_path = output_dir / "API_Security_Audit_Report.docx"
    doc.save(str(report_path))
    print(f"📄 Comprehensive report saved to: {report_path}")

def main():
    output_dir = Path(".")  # Aanpassen indien nodig
    create_audit_report(output_dir)

if __name__ == "__main__":
    main()
