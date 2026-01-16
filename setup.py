########################################################
# APISCAN - setup                                      #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
########################################################

import sys
import os
import subprocess
import platform
from pathlib import Path

# ==========================================================
# DEFAULT CONFIG / FALLBACK STRINGS
# ==========================================================
env_example = """# ===== APISCAN CONFIG =====
# Copy to .env and update values as needed

# AI Provider: openai | anthropic | ollama
LLM_PROVIDER=openai
LLM_API_KEY=

# Optional: base URL for live scanning modes
APISCAN_BASE_URL=

# Local Ollama example
# OLLAMA_HOST=http://localhost:11434
"""

# Default .gitignore for Python + APISCAN
gitignore = """# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.env

# Logs / reports
logs/
output/
reports/
*.html
*.pdf

# Virtual envs
venv/
env/
"""

# Quick Start guide (printed after setup)
guide = """
APISCAN QUICK START
-------------------

1) Configure .env with your LLM provider + API key
2) Run a scan:
   python apiscan.py --url https://target/api --swagger ./openapi.json

3) Token flow example:
   python apiscan.py --url https://target/api --flow token --token ABC123XYZ

For help:
   python apiscan.py --help
"""

# NOTE: This is the single fallback source of truth for dependencies.
requirements = """# Networking & HTTP
requests>=2.31.0
urllib3>=2.2.0
tqdm>=4.66.0

# Authentication
requests_ntlm>=1.2.0
requests-oauthlib>=1.3.1
oauthlib>=3.2.2
PyJWT>=2.8.0
sslyze>=6.2.0

# Parsing & HTML
beautifulsoup4>=4.12.2
lxml>=4.9.3
httpx>=0.27.0

# Output
colorama>=0.4.6
markdown2>=2.4.10

# AI Clients
openai>=1.0.0,<2.0.0
anthropic>=0.67.0

# Typing & util
python-dateutil>=2.8.2
typing_extensions>=4.15.0
PyYAML>=6.0.2
openapi-spec-validator>=0.7.2
tenacity>=8.2.0
python-dotenv>=1.0.0
pydantic>=2.0.0
"""


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


#================ print_header ##########
def print_header(text):
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(60)}{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")


#================ print_success ##########
def print_success(text):
    print(f"{Colors.GREEN}{text}{Colors.END}")


#================ print_warning ##########
def print_warning(text):
    print(f"{Colors.YELLOW}{text}{Colors.END}")


#================ print_error ##########
def print_error(text):
    print(f"{Colors.RED}{text}{Colors.END}")


#================ print_info ##########
def print_info(text):
    print(f"{Colors.CYAN}{text}{Colors.END}")


#================ check_python_version ##########
def check_python_version():
    print_header("PYTHON VERSION CHECK")

    required = (3, 8)
    current = sys.version_info[:2]

    print_info(f"Python version: {sys.version}")

    if current >= required:
        print_success(f"Python {current[0]}.{current[1]} meets minimum requirement {required[0]}.{required[1]}")
        return True

    print_error(f"Python {current[0]}.{current[1]} is too old. Minimum is {required[0]}.{required[1]}")
    return False


#================ _parse_fallback_requirements ##########
def _parse_fallback_requirements(req_text: str) -> list[str]:
    deps: list[str] = []
    for raw in req_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        deps.append(line)
    return deps


#================ _package_name_from_spec ##########
def _package_name_from_spec(spec: str) -> str:
    
    for sep in ["==", ">=", "<=", "!=", "~=", ">", "<"]:
        if sep in spec:
            return spec.split(sep, 1)[0].strip()
    return spec.strip()


#================ install_dependencies ##########
def install_dependencies():
    print_header("INSTALLING DEPENDENCIES")

    def get_installed_version(package_name):
        try:
            import importlib.metadata
            return importlib.metadata.version(package_name)
        except importlib.metadata.PackageNotFoundError:
            try:
                import pkg_resources
                return pkg_resources.get_distribution(package_name).version
            except Exception:
                return None
        except ImportError:
            try:
                import pkg_resources
                return pkg_resources.get_distribution(package_name).version
            except Exception:
                return None

    def install_package_list(packages, description):
        print_info(description)
        success_count = 0
        fail_count = 0

        for dep in packages:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
                print_success(f"Installed: {dep}")
                success_count += 1
            except subprocess.CalledProcessError as e:
                print_warning(f"Could not install {dep}: {e}")
                fail_count += 1

        return success_count, fail_count

    try:
        print_info("Checking existing packages...")
        openai_version = get_installed_version("openai")
        if openai_version:
            print_info(f"Current OpenAI version: {openai_version}")
            if openai_version.startswith("2."):
                print_warning("OpenAI 2.x detected - will try to pin to 1.x for compatibility")
        else:
            print_info("OpenAI not installed")

        print_info("Upgrading pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])

        req_file = Path("requirements.txt")
        used_requirements = False
        fail_count = 0

        if req_file.exists():
            print_info(f"Found {req_file}, installing full dependency set...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(req_file)])
                print_success(f"Installed dependencies from {req_file}")
                used_requirements = True
            except subprocess.CalledProcessError as e:
                print_error(f"Failed to install from {req_file}: {e}")
                print_warning("Falling back to internal requirements list")
                fail_count += 1

       
        if not used_requirements:
            deps = _parse_fallback_requirements(requirements)

            print_info("Fallback dependency list (requirements.txt not used):")
            for dep in deps:
                print(f"  - {dep}")

            print_info("\nInstalling fallback dependencies...")
            _, dep_fail = install_package_list(deps, "Installing dependencies...")
            fail_count += dep_fail


        openai_version = get_installed_version("openai")
        if openai_version:
            if openai_version.startswith("2."):
                print_warning("OpenAI 2.x still detected after installation. Forcing 1.x...")
                try:
                    subprocess.check_call([
                        sys.executable,
                        "-m",
                        "pip",
                        "install",
                        "openai>=1.0.0,<2.0.0",
                        "--force-reinstall"
                    ])
                    openai_version = get_installed_version("openai")
                    print_success(f"OpenAI pinned to version {openai_version}")
                except subprocess.CalledProcessError as e:
                    print_warning(f"Could not force OpenAI 1.x: {e}")
        else:
            print_warning("OpenAI not found after installation, consider installing it manually")

        print_header("INSTALLATION VERIFICATION")
        deps_for_check = _parse_fallback_requirements(requirements)
        packages_to_check = [_package_name_from_spec(d) for d in deps_for_check]

        verified = []
        failed = []

        for package in packages_to_check:
            version = get_installed_version(package)
            if version:
                print_success(f"{package}: version {version}")
                verified.append(package)
                if package == "openai" and version.startswith("2."):
                    print_warning("OpenAI 2.x detected - potential compatibility issues remain")
            else:
                print_error(f"{package}: NOT installed")
                failed.append(package)

        if not failed:
            print_success("\nAll core dependencies appear to be installed correctly")
        else:
            print_warning(f"\n{len(failed)} packages not installed or not detected: {', '.join(failed)}")
            print_info("Try installing them manually, for example:")
            for package in failed:
                print(f"  pip install {package}")

        return len(failed) == 0 and fail_count == 0

    except KeyboardInterrupt:
        print_error("\nInstallation cancelled by user")
        return False
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


#================ check_environment ##########
def check_environment():
    print_header("ENVIRONMENT CHECK")

    issues = []
    warnings = []

    if Path(".env").exists():
        print_success(".env file found")
    else:
        warnings.append("No .env file found")
        print_warning("No .env file - create a .env with your configuration")

    env_checks = [
        ("LLM_API_KEY", "For AI analysis", False, None),
        ("LLM_PROVIDER", "For LLM choice", True, "openai_compat"),
        ("APISCAN_BASE_URL", "For live scanning", False, None),
    ]

    for var, description, required, default in env_checks:
        value = os.getenv(var)
        if value:
            masked = value[:4] + "***" + value[-4:] if len(value) > 8 else "***"
            print_success(f"{var}: {masked} ({description})")
        elif default is not None:
            print_info(f"{var}: Not set, using default '{default}'")
            warnings.append(f"{var} using default value")
        elif required:
            print_error(f"{var}: NOT FOUND ({description})")
            issues.append(var)
        else:
            print_warning(f"{var}: Not set ({description})")
            warnings.append(var)

    return issues, warnings


#================ create_example_env ##########
def create_example_env():
    print_header("CREATING .ENV EXAMPLE")

    env_path = Path(".env.example")
    env_path.write_text(env_example, encoding="utf-8")
    print_success(f".env.example created at {env_path}")

    if not Path(".gitignore").exists():
        Path(".gitignore").write_text(gitignore, encoding="utf-8")
        print_success(".gitignore created")


#================ check_custom_modules ##########
def check_custom_modules():
    print_header("CUSTOM MODULES CHECK")

    modules = [
        ("report_utils", "For advanced reporting", False),
        ("build_review", "For review dashboards", False),
    ]

    missing = []

    for module, description, required in modules:
        try:
            __import__(module)
            print_success(f"{module}: {description}")
        except ImportError:
            if required:
                print_error(f"{module}: MISSING ({description})")
                missing.append(module)
            else:
                print_warning(f"{module}: Not found ({description})")

    return missing


#================ create_requirements_txt ##########
def create_requirements_txt():
    print_header("CREATING REQUIREMENTS.TXT")

    req_path = Path("requirements.txt")
    req_path.write_text(requirements, encoding="utf-8")
    print_success(f"requirements.txt created at {req_path}")


#================ show_quick_start ##########
def show_quick_start():
    print_header("QUICK START GUIDE")
    print(guide)


#================ main ##########
def main():
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("")
    print("                APISCAN SETUP WIZARD  BY Perry Mertens (c) 2026                     ")
    print("                    v4.0                                  ")
    print("")
    print(f"{Colors.END}")

    skip_deps = "--skip-deps" in sys.argv
    create_examples = "--create-examples" in sys.argv
    minimal = "--minimal" in sys.argv

    if not check_python_version():
        print_error("Python version does not meet requirements.")
        sys.exit(1)

    if not skip_deps:
        if not install_dependencies():
            print_error("Dependency installation failed.")
            sys.exit(1)
    else:
        print_warning("Dependency check skipped")

    if create_examples or not Path(".env.example").exists():
        create_example_env()
        create_requirements_txt()

    issues, warnings = check_environment()
    missing_modules = check_custom_modules()

    print_header("SETUP SUMMARY")

    if issues:
        print_error(f"{len(issues)} critical issues found:")
        for issue in issues:
            print(f"  - {issue}")
        print(f"\n{Colors.YELLOW}Solutions:{Colors.END}")
        for issue in issues:
            if issue == "LLM_API_KEY":
                print("  - Set LLM_API_KEY in .env or export it")
            elif issue.startswith("APISCAN_"):
                print(f"  - Configure {issue} in .env file")
    else:
        print_success("No critical issues found!")

    if warnings:
        print(f"\n{Colors.YELLOW}{len(warnings)} warnings:{Colors.END}")
        for warning in warnings:
            print(f"  - {warning}")

    if missing_modules:
        print(f"\n{Colors.YELLOW}{len(missing_modules)} missing modules:{Colors.END}")
        for module in missing_modules:
            print(f"  - {module}")
        print("  These modules are needed for full functionality")

    if not minimal:
        show_quick_start()

    print(f"\n{Colors.GREEN}{Colors.BOLD}Setup completed!{Colors.END}")
    print(f"{Colors.CYAN}Start with: python apiscan.py --url https://api.sample.com --swagger file.xxx --flow token --token any... {Colors.END}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Setup cancelled{Colors.END}")
        sys.exit(0)
