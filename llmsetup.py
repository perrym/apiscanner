########################################################
# APISCAN - AI Security Scanner Module                 #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# For use with --api11 flag or AI features             #
########################################################

import sys
import os
import subprocess
import json
import time
import platform
from pathlib import Path

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

#================ print_header: ========================
def print_header(text):
    print(f"\n{Colors.MAGENTA}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(60)}{Colors.END}")
    print(f"{Colors.MAGENTA}{'='*60}{Colors.END}")

#================ print_success: ========================
def print_success(text):
    print(f"{Colors.GREEN}[OK]{Colors.END} {text}")

#================ print_warning: ========================
def print_warning(text):
    print(f"{Colors.YELLOW}[warning]{Colors.END} {text}")

#================ print_error: ========================
def print_error(text):
    print(f"{Colors.RED}[error]{Colors.END} {text}")

#================ print_info: ========================
def print_info(text):
    print(f"{Colors.CYAN}[info]{Colors.END} {text}")

#================ detect_shell: ========================
def detect_shell():
    shell_info = {
        "os": platform.system().lower(),
        "shell": None,
        "terminal": None
    }
    
    if shell_info["os"] == "windows":
        shell_env = os.environ.get("SHELL", "")
        if "PSModulePath" in os.environ and not shell_env:
            shell_info["shell"] = "powershell"
        elif "PWD" in os.environ and "Program Files\\PowerShell" in os.environ.get("PWD", ""):
            shell_info["shell"] = "powershell"
        elif "WT_SESSION" in os.environ:
            shell_info["shell"] = "powershell"
        else:
            shell_info["shell"] = "cmd"
        
        if "WT_SESSION" in os.environ:
            shell_info["terminal"] = "windows_terminal"
        elif "ConEmuANSI" in os.environ:
            shell_info["terminal"] = "conemu"
        elif "MSYSTEM" in os.environ:
            shell_info["terminal"] = "git_bash"
            shell_info["shell"] = "bash"
        else:
            shell_info["terminal"] = "default"
    
    elif shell_info["os"] in ["linux", "darwin"]:
        shell = os.environ.get("SHELL", "")
        if "bash" in shell:
            shell_info["shell"] = "bash"
        elif "zsh" in shell:
            shell_info["shell"] = "zsh"
        elif "fish" in shell:
            shell_info["shell"] = "fish"
        else:
            shell_info["shell"] = "sh"
        
        term = os.environ.get("TERM", "")
        if "xterm" in term:
            shell_info["terminal"] = "xterm"
        elif "gnome" in term.lower():
            shell_info["terminal"] = "gnome-terminal"
        elif "konsole" in term.lower():
            shell_info["terminal"] = "konsole"
        elif "alacritty" in term.lower():
            shell_info["terminal"] = "alacritty"
        else:
            shell_info["terminal"] = "unknown"
    
    return shell_info

LLM_PROVIDERS = {
    "ollama": {
        "name": "Ollama (Local)",
        "package": "",
        "client": "openai",
        "env_vars": ["OLLAMA_HOST", "OLLAMA_API_KEY"],
        "auth_type": "none",
        "base_url": "http://localhost:11434/v1",
        "models": [
            "llama3.2", "llama3.1", "llama3",
            "llama2", "llama2:13b", "llama2:70b",
            "mistral", "mixtral", "mixtral:8x7b",
            "codellama", "phi3", "gemma", "gemma2",
            "qwen", "qwen2", "qwen2.5"
        ],
        "required": False,
        "description": "Local LLMs via Ollama (free, offline)"
    },
    "openai": {
    "name": "OpenAI",
    "package": "openai>=1.0.0",
    "client": "openai",
    "env_vars": ["OPENAI_API_KEY", "LLM_API_KEY"],
    "auth_type": "api_key",
    "base_url": "https://api.openai.com/v1",
    "api_style": "chat_completions",
    "models": [
        "gpt-4.1",
        "gpt-4.1-mini",
        "gpt-4o",
        "gpt-4o-mini",
        "o3-mini",
        "o1",
        "o1-mini",
        "gpt-4-turbo",
        "gpt-4-turbo-preview",
        "gpt-3.5-turbo",
        "gpt-3.5-turbo-instruct"
    ],
    "required": False,
    "description": "Official OpenAI API (GPT-4.1 / GPT-4o / o-series)"
},

    "anthropic": {
        "name": "Anthropic Claude",
        "package": "anthropic>=0.67.0",
        "client": "anthropic",
        "env_vars": ["ANTHROPIC_API_KEY"],
        "auth_type": "api_key",
        "base_url": "https://api.anthropic.com",
        "models": [
            "claude-3-5-sonnet-20241022", "claude-3-5-sonnet",
            "claude-3-opus", "claude-3-sonnet", "claude-3-haiku"
        ],
        "required": False,
        "description": "Claude AI from Anthropic"
    },
    "deepseek": {
        "name": "DeepSeek",
        "package": "openai>=1.0.0",
        "client": "openai",
        "env_vars": ["DEEPSEEK_API_KEY"],
        "auth_type": "api_key",
        "base_url": "https://api.deepseek.com",
        "models": ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"],
        "required": False,
        "description": "DeepSeek AI (cost-effective alternative)"
    }
}

#================ create_shell_specific_files: ========================
def create_shell_specific_files(all_config, shell_info):
    os_type = shell_info["os"]
    shell = shell_info["shell"]
    
    scripts_created = []
    
    env_content = []
    for key, value in all_config.items():
        if value and not key.startswith("_"):
            env_content.append(f"{key}={value}")
    
    env_file = Path(".env")
    env_file.write_text("\n".join(env_content), encoding="utf-8")
    scripts_created.append(".env")
    
    if os_type == "windows":
        ps_content = [
            "# APISCAN Environment Setup for PowerShell",
            "# Generated by llmsetup.py",
            "# NO ADMIN RIGHTS NEEDED",
            "",
            "Write-Host \"Setting APISCAN environment variables...\" -ForegroundColor Yellow",
            "",
        ]
        
        for key, value in all_config.items():
            if value and not key.startswith("_"):
                escaped_ps = value.replace('"', '`"').replace('$', '`$')
                ps_content.append(f'$env:{key} = "{escaped_ps}"')
        
        ps_content.extend([
            "",
            'Write-Host ""',
            'Write-Host "APISCAN environment configured!" -ForegroundColor Green',
            'Write-Host ""',
            'Write-Host "LLM Provider: $env:LLM_PROVIDER" -ForegroundColor Cyan',
            'Write-Host "Model: $env:LLM_MODEL" -ForegroundColor Cyan',
            'if ($env:OLLAMA_HOST) {',
            '    Write-Host "Ollama Host: $env:OLLAMA_HOST" -ForegroundColor Cyan',
            '}',
            'Write-Host ""',
        ])
        
        ps_file = Path("apiscan_env.ps1")
        ps_file.write_text("\n".join(ps_content), encoding="utf-8")
        scripts_created.append("apiscan_env.ps1")
        
        bat_content = [
            "@echo off",
            "REM APISCAN Environment Setup for CMD",
            "REM NO ADMIN RIGHTS NEEDED",
            "",
            "echo Setting APISCAN environment variables...",
            "",
        ]
        
        for key, value in all_config.items():
            if value and not key.startswith("_"):
                escaped_cmd = value.replace("%", "%%")
                bat_content.append(f"set {key}={escaped_cmd}")
        
        bat_content.extend([
            "",
            "echo.",
            "echo  APISCAN environment configured!",
            "echo.",
            "echo LLM Provider: %LLM_PROVIDER%",
            "echo Model: %LLM_MODEL%",
            "if not \"%OLLAMA_HOST%\"==\"\" echo Ollama Host: %OLLAMA_HOST%",
            "echo.",
            "pause"
        ])
        
        bat_file = Path("apiscan_env.bat")
        bat_file.write_text("\r\n".join(bat_content), encoding="utf-8")
        scripts_created.append("apiscan_env.bat")
    
    else:
        bash_content = [
            "#!/bin/bash",
            "# APISCAN Environment Setup for Bash",
            "",
            "echo \"Setting APISCAN environment variables...\"",
            "",
        ]
        
        for key, value in all_config.items():
            if value and not key.startswith("_"):
                escaped = value.replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
                bash_content.append(f'export {key}="{escaped}"')
        
        bash_content.extend([
            "",
            'echo ""',
            'echo " APISCAN environment configured!"',
            'echo ""',
            'echo "LLM Provider: $LLM_PROVIDER"',
            'echo "Model: $LLM_MODEL"',
            'if [ -n "$OLLAMA_HOST" ]; then',
            '    echo "Ollama Host: $OLLAMA_HOST"',
            'fi',
            'echo ""',
        ])
        
        bash_file = Path("apiscan_env.sh")
        bash_file.write_text("\n".join(bash_content), encoding="utf-8")
        bash_file.chmod(0o755)
        scripts_created.append("apiscan_env.sh")
        
        fish_content = [
            "# APISCAN Environment Setup for Fish shell",
            "",
            'echo "Setting APISCAN environment variables..."',
            "",
        ]
        
        for key, value in all_config.items():
            if value and not key.startswith("_"):
                escaped = value.replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
                fish_content.append(f'set -gx {key} "{escaped}"')
        
        fish_content.extend([
            "",
            'echo ""',
            'echo " APISCAN environment configured!"',
            'echo ""',
            'echo "LLM Provider: $LLM_PROVIDER"',
            'echo "Model: $LLM_MODEL"',
            'if test -n "$OLLAMA_HOST"',
            '    echo "Ollama Host: $OLLAMA_HOST"',
            'end',
            'echo ""'
        ])
        
        fish_file = Path("apiscan_env.fish")
        fish_file.write_text("\n".join(fish_content), encoding="utf-8")
        scripts_created.append("apiscan_env.fish")
    
    return scripts_created

#================ show_shell_instructions: ========================
def show_shell_instructions(shell_info, scripts_created):
    os_type = shell_info["os"]
    shell = shell_info["shell"]
    
    print_header(f"SHELL CONFIGURATION - {shell.upper()} ({os_type.upper()})")
    
    instructions = []
    
    if os_type == "windows":
        if shell == "powershell":
            instructions.extend([
                f"{Colors.CYAN}PowerShell Instructions:{Colors.END}",
                "",
                f"{Colors.BOLD}NO ADMIN RIGHTS NEEDED!{Colors.END}",
                "",
                f"{Colors.BOLD}1. Load environment variables:{Colors.END}",
                f"   {Colors.YELLOW}.\\apiscan_env.ps1{Colors.END}",
                "",
                f"{Colors.BOLD}2. Alternative:{Colors.END}",
                f"   {Colors.YELLOW}powershell -ExecutionPolicy Bypass -File apiscan_env.ps1{Colors.END}",
                "",
                f"{Colors.BOLD}3. Test environment:{Colors.END}",
                f"   {Colors.YELLOW}python test_env.py{Colors.END}",
                "",
            ])
            
            if "apiscan_env.ps1" in scripts_created:
                instructions.extend([
                    "",
                    f"{Colors.GREEN} Script created: apiscan_env.ps1{Colors.END}",
                    f"{Colors.YELLOW}Run with:{Colors.END}",
                    f"{Colors.YELLOW}    .\\apiscan_env.ps1{Colors.END}",
                ])
        
        else:
            instructions.extend([
                f"{Colors.CYAN}CMD Command Prompt Instructions:{Colors.END}",
                "",
                f"{Colors.BOLD}NO ADMIN RIGHTS NEEDED!{Colors.END}",
                "",
                f"{Colors.BOLD}1. Load environment variables:{Colors.END}",
                f"   {Colors.YELLOW}apiscan_env.bat{Colors.END}",
                "",
                f"{Colors.BOLD}2. Test environment:{Colors.END}",
                f"   {Colors.YELLOW}python test_env.py{Colors.END}",
            ])
            
            if "apiscan_env.bat" in scripts_created:
                instructions.extend([
                    "",
                    f"{Colors.GREEN} Script created: apiscan_env.bat{Colors.END}",
                    f"{Colors.YELLOW}Run with:{Colors.END}",
                    f"{Colors.YELLOW}    apiscan_env.bat{Colors.END}",
                ])
    
    else:
        if shell == "fish":
            instructions.extend([
                f"{Colors.CYAN}Fish Shell Instructions:{Colors.END}",
                "",
                f"{Colors.BOLD}1. Load environment variables:{Colors.END}",
                f"   {Colors.YELLOW}source apiscan_env.fish{Colors.END}",
                "",
                f"{Colors.BOLD}2. Test environment:{Colors.END}",
                f"   {Colors.YELLOW}python test_env.py{Colors.END}",
            ])
            
            if "apiscan_env.fish" in scripts_created:
                instructions.extend([
                    "",
                    f"{Colors.GREEN} Script created: apiscan_env.fish{Colors.END}",
                    f"{Colors.YELLOW}Run with:{Colors.END}",
                    f"{Colors.YELLOW}    source apiscan_env.fish{Colors.END}"
                ])
        
        else:
            shell_name = "Zsh" if shell == "zsh" else "Bash"
            
            instructions.extend([
                f"{Colors.CYAN}{shell_name} Shell Instructions:{Colors.END}",
                "",
                f"{Colors.BOLD}1. Load environment variables:{Colors.END}",
                f"   {Colors.YELLOW}source apiscan_env.sh{Colors.END}",
                "",
                f"{Colors.BOLD}2. Test environment:{Colors.END}",
                f"   {Colors.YELLOW}python test_env.py{Colors.END}",
            ])
            
            if "apiscan_env.sh" in scripts_created:
                instructions.extend([
                    "",
                    f"{Colors.GREEN} Script created: apiscan_env.sh{Colors.END}",
                    f"{Colors.YELLOW}Run with:{Colors.END}",
                    f"{Colors.YELLOW}    source apiscan_env.sh{Colors.END}",
                ])
    
    instructions.extend([
        "",
        f"{Colors.CYAN}Universal .env file:{Colors.END}",
        f"{Colors.GREEN} File created: .env{Colors.END}",
    ])
    
    print("\n".join(instructions))

#================ create_test_env_script: ========================
def create_test_env_script():
#APISCAN Environment Variables Test Script
#Run: python test_env.py
    
    test_file = Path("test_env.py")
    test_file.write_text(test_script, encoding="utf-8")
    print_success("test_env.py created - use this to test your setup")
    return test_file

#================ test_environment_setup: ========================
def test_environment_setup():
    print_header("TESTING ENVIRONMENT SETUP")
    
    test_file = create_test_env_script()
    
    print_info("Running environment test...")
    print_info("Note: Environment variables are NOT set in this Python process yet.")
    
    shell_info = detect_shell()
    
    print(f"\n{Colors.BOLD}Follow these steps:{Colors.END}")
    
    if shell_info["os"] == "windows":
        if shell_info["shell"] == "powershell":
            print(f"1. Open a NEW PowerShell window")
            print(f"2. Run: {Colors.YELLOW}.\\apiscan_env.ps1{Colors.END}")
            print(f"3. Run: {Colors.YELLOW}python test_env.py{Colors.END}")
        else:
            print(f"1. Open a NEW CMD window")
            print(f"2. Run: {Colors.YELLOW}apiscan_env.bat{Colors.END}")
            print(f"3. Run: {Colors.YELLOW}python test_env.py{Colors.END}")
    else:
        if shell_info["shell"] == "fish":
            print(f"1. Open a NEW terminal")
            print(f"2. Run: {Colors.YELLOW}source apiscan_env.fish{Colors.END}")
            print(f"3. Run: {Colors.YELLOW}python test_env.py{Colors.END}")
        else:
            print(f"1. Open a NEW terminal")
            print(f"2. Run: {Colors.YELLOW}source apiscan_env.sh{Colors.END}")
            print(f"3. Run: {Colors.YELLOW}python test_env.py{Colors.END}")
    
    print(f"\n{Colors.YELLOW} Note:{Colors.END}")
    print("You need to open a NEW terminal/shell after running the setup scripts.")
    
    return True

#================ select_providers: ========================
def select_providers():
    print_header("SELECT LLM PROVIDERS")
    print("Choose which AI providers you want to configure:\n")
    
    for i, (provider_id, provider) in enumerate(LLM_PROVIDERS.items(), 1):
        print(f"[{i}] {provider['name']:25}")
        print(f"    {provider['description']}")
        
        if provider_id == "ollama":
            print(f"    {Colors.YELLOW}Ollama Host: http://localhost:11434 (default){Colors.END}")
        
        configured = any(os.getenv(var) for var in provider["env_vars"])
        if configured:
            print(f"    {Colors.GREEN} Already configured{Colors.END}")
        print()
    
    print(f"[5] Exit Configuration")
    print(f"    Return to main setup")
    print()
    
    print(f"{Colors.YELLOW}Select providers (e.g. '1' for Ollama or '1,2,3' for multiple, '5' to exit):{Colors.END}")
    selection = input("> ").strip().lower()
    
    if selection == "5" or selection == "exit":
        print_info("Exiting provider configuration")
        return []
    
    selected_providers = []
    
    if selection == "all":
        selected_providers = list(LLM_PROVIDERS.keys())
    else:
        try:
            indices = [int(x.strip()) for x in selection.split(',')]
            provider_ids = list(LLM_PROVIDERS.keys())
            for idx in indices:
                if 1 <= idx <= len(provider_ids):
                    selected_providers.append(provider_ids[idx-1])
                elif idx == 5:
                    print_info("Exiting provider configuration")
                    return []
        except ValueError:
            print_error("Invalid selection. Please try again.")
            return select_providers()
    
    return selected_providers

#================ configure_provider: ========================
def configure_provider(provider_id):
    provider = LLM_PROVIDERS[provider_id]
    
    print(f"\n{Colors.BOLD}Configuring {provider['name']}{Colors.END}")
    print(f"{provider['description']}")
    
    config = {}
    
    if provider_id == "ollama":
        ollama_host_default = "http://localhost:11434"
        print_info(f"OLLAMA_HOST will be set to: {ollama_host_default}")
        config["OLLAMA_HOST"] = ollama_host_default
        
        response = input(f"Use a different OLLAMA_HOST? (y/N): ").strip().lower()
        if response == 'y':
            new_host = input(f"OLLAMA_HOST [{ollama_host_default}]: ").strip()
            if new_host:
                config["OLLAMA_HOST"] = new_host
        
        current_key = os.getenv("OLLAMA_API_KEY", "")
        if current_key:
            masked = current_key[:4] + "***" + current_key[-4:] if len(current_key) > 8 else "***"
            print_info(f"OLLAMA_API_KEY is already set: {masked}")
            response = input("Change? (y/N): ").strip().lower()
            if response == 'y':
                new_key = input("OLLAMA_API_KEY (optional): ").strip()
                if new_key:
                    config["OLLAMA_API_KEY"] = new_key
            else:
                config["OLLAMA_API_KEY"] = current_key
        else:
            new_key = input("OLLAMA_API_KEY (optional, press Enter to skip): ").strip()
            if new_key:
                config["OLLAMA_API_KEY"] = new_key
    
    else:
        for env_var in provider["env_vars"]:
            current = os.getenv(env_var, "")
            
            if current:
                if any(keyword in env_var.lower() for keyword in ["key", "secret", "token"]):
                    masked = current[:4] + "***" + current[-4:] if len(current) > 8 else "***"
                    print_info(f"{env_var} is already set: {masked}")
                else:
                    print_info(f"{env_var} is already set: {current}")
                
                response = input(f"Change? (y/N): ").strip().lower()
                if response == 'y':
                    new_value = input(f"{env_var}: ").strip()
                    if new_value:
                        config[env_var] = new_value
                else:
                    config[env_var] = current
            else:
                new_value = input(f"{env_var}: ").strip()
                if new_value:
                    config[env_var] = new_value
    
    if provider["models"]:
        print(f"\nAvailable models for {provider['name']}:")
        
        for i, model in enumerate(provider["models"][:10], 1):
            print(f"  [{i}] {model}")
        
        if len(provider["models"]) > 10:
            print(f"  ... and {len(provider['models']) - 10} more")
        
        model_choice = input(f"\nChoose model [default: {provider['models'][0]}]: ").strip()
        if model_choice.isdigit() and 1 <= int(model_choice) <= len(provider["models"]):
            selected_model = provider["models"][int(model_choice) - 1]
        elif model_choice:
            matching_models = [m for m in provider["models"] if model_choice.lower() in m.lower()]
            if matching_models:
                selected_model = matching_models[0]
                print_info(f"Selected: {selected_model}")
            else:
                selected_model = model_choice
                print_warning(f"Model '{model_choice}' not in list, using custom name")
        else:
            selected_model = provider["models"][0]
        
        config["LLM_MODEL"] = selected_model
    
    config["LLM_PROVIDER"] = provider_id
    
    config["LLM_TEMPERATURE"] = "0.0"
    config["LLM_MAX_TOKENS"] = "4096"
    
    if provider_id == "ollama":
        print_success(f"Ollama configured!")
        print_info(f"   Host: {config.get('OLLAMA_HOST', 'http://localhost:11434')}")
        print_info(f"   Model: {config.get('LLM_MODEL', 'llama3:latest')}")
        print_info(f"   Ensure Ollama is running: ollama serve")
    
    return config

#================ create_llm_config_file_shell_aware: ========================
def create_llm_config_file_shell_aware(providers_config):
    print_header("CREATING LLM CONFIGURATION")
    
    shell_info = detect_shell()
    print_info(f"Detected: {shell_info['os'].upper()} - {shell_info['shell'].upper()} - {shell_info['terminal']}")
    
    all_config = {}
    for provider_id, config in providers_config.items():
        all_config.update(config)
    
    if "ollama" in providers_config and "OLLAMA_HOST" not in all_config:
        all_config["OLLAMA_HOST"] = "http://localhost:11434"
        print_success(f"OLLAMA_HOST automatically set to: {all_config['OLLAMA_HOST']}")
    
    default_settings = {
        "LLM_TEMPERATURE": "0.0",
        "LLM_MAX_TOKENS": "4096",
        "LLM_TIMEOUT": "60",
        "LLM_MAX_RETRIES": "3"
    }
    
    for key, value in default_settings.items():
        if key not in all_config:
            all_config[key] = value
    
    print("\nChoose configuration method:")
    print("  [1] .env file + Shell scripts (recommended)")
    print("  [2] .env file only")
    print("  [3] Shell scripts only")
    print("  [4] Everything (.env + scripts + json)")
    
    choice = input("Choose (1-4): ").strip() or "1"
    
    created_files = []
    
    if choice in ["1", "2", "4"]:
        env_content = [
            "# APISCAN LLM Configuration",
            f"# Generated by llmsetup.py - {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"# OS: {shell_info['os']}, Shell: {shell_info['shell']}",
            ""
        ]
        
        for key, value in all_config.items():
            if value and not key.startswith("_"):
                env_content.append(f"{key}={value}")
        
        env_file = Path(".env")
        env_file.write_text("\n".join(env_content), encoding="utf-8")
        created_files.append(".env")
        print_success(f".env file created")
    
    if choice in ["1", "3", "4"]:
        scripts = create_shell_specific_files(all_config, shell_info)
        created_files.extend(scripts)
        for script in scripts:
            if script != ".env":
                print_success(f"{script} created")
    
    if choice == "4":
        config_data = {
            "version": "2.1",
            "shell_info": shell_info,
            "providers": providers_config,
            "config": all_config,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        json_path = Path("llm_config.json")
        json_path.write_text(json.dumps(config_data, indent=2, ensure_ascii=False), encoding="utf-8")
        created_files.append("llm_config.json")
        print_success("llm_config.json created")
    
    if created_files:
        show_shell_instructions(shell_info, created_files)
    
    return True

#================ show_quick_setup_guide: ========================
def show_quick_setup_guide(shell_info):
    print_header("QUICK SETUP GUIDE")
    
    guide = []
    
    if shell_info["os"] == "windows":
        if shell_info["shell"] == "powershell":
            guide.extend([
                f"{Colors.BOLD}PowerShell Quick Setup:{Colors.END}",
                "",
                "1. First: Set environment variables",
                f"   {Colors.YELLOW}.\\apiscan_env.ps1{Colors.END}",
                "",
                "2. If ExecutionPolicy error:",
                f"   {Colors.YELLOW}Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser{Colors.END}",
                f"   {Colors.YELLOW}Or: powershell -ExecutionPolicy Bypass -File apiscan_env.ps1{Colors.END}",
                "",
                "3. Then: Test your setup",
                f"   {Colors.YELLOW}python test_env.py{Colors.END}",
                "",
                "4. Finally: Run APISCAN with AI",
                f"   {Colors.YELLOW}python apiscan.py --api11 --target https://api.example.com{Colors.END}"
            ])
        else:
            guide.extend([
                f"{Colors.BOLD}CMD Quick Setup:{Colors.END}",
                "",
                "1. First: Set environment variables",
                f"   {Colors.YELLOW}apiscan_env.bat{Colors.END}",
                "",
                "2. Then: Test your setup",
                f"   {Colors.YELLOW}python test_env.py{Colors.END}",
                "",
                "3. Finally: Run APISCAN with AI",
                f"   {Colors.YELLOW}python apiscan.py --api11 --target https://api.example.com{Colors.END}"
            ])
    else:
        if shell_info["shell"] == "fish":
            guide.extend([
                f"{Colors.BOLD}Fish Shell Quick Setup:{Colors.END}",
                "",
                "1. First: Set environment variables",
                f"   {Colors.YELLOW}source apiscan_env.fish{Colors.END}",
                "",
                "2. Then: Test your setup",
                f"   {Colors.YELLOW}python test_env.py{Colors.END}",
                "",
                "3. Finally: Run APISCAN with AI",
                f"   {Colors.YELLOW}python apiscan.py --api11 --target https://api.example.com{Colors.END}"
            ])
        else:
            shell_name = "Zsh" if shell_info["shell"] == "zsh" else "Bash"
            guide.extend([
                f"{Colors.BOLD}{shell_name} Quick Setup:{Colors.END}",
                "",
                "1. First: Set environment variables",
                f"   {Colors.YELLOW}source apiscan_env.sh{Colors.END}",
                "",
                "2. Then: Test your setup",
                f"   {Colors.YELLOW}python test_env.py{Colors.END}",
                "",
                "3. Finally: Run APISCAN with AI",
                f"   {Colors.YELLOW}python apiscan.py --api11 --target https://api.example.com{Colors.END}"
            ])
    
    guide.extend([
        "",
        f"{Colors.CYAN}For Ollama users:{Colors.END}",
        "1. Download and install Ollama: https://ollama.com",
        "2. Start Ollama service:",
        "    Windows: Open Ollama app",
        "    Linux/macOS: ollama serve",
        "3. Pull a model: ollama pull llama3",
        "4. Test Ollama: curl http://localhost:11434/api/tags"
    ])
    
    print("\n".join(guide))

#================ main: ========================
def main():
    print(f"{Colors.BOLD}{Colors.MAGENTA}")
    print("")
    print("               APISCAN LLM/AI SETUP v2.1                  ")
    print("              Multi-Shell & Ollama Support                ")
    print("")
    print(f"{Colors.END}")
    
    print(f"{Colors.CYAN}Features:{Colors.END}")
    print("   Multi-shell support (CMD, PowerShell, Bash, Zsh, Fish)")
    print("   Automatic shell detection")
    print(f"   {Colors.GREEN}NO ADMIN RIGHTS NEEDED{Colors.END}")
    print(f"   {Colors.YELLOW}Automatic OLLAMA_HOST configuration{Colors.END}")
    print("   .env + shell scripts generation")
    print(f"   {Colors.CYAN}Permanent test_env.py script{Colors.END}")
    
    shell_info = detect_shell()
    print_info(f"Detected: {shell_info['os'].upper()} - {shell_info['shell'].upper()}")
    
    selected_providers = select_providers()
    
    if not selected_providers:
        print_warning("No providers selected. Setup cancelled.")
        return
    
    providers_config = {}
    for provider_id in selected_providers:
        config = configure_provider(provider_id)
        if config:
            providers_config[provider_id] = config
    
    if providers_config:
        create_llm_config_file_shell_aware(providers_config)
    else:
        print_warning("No providers configured")
        return
    
    create_test_env_script()
    
    print("\n" + "="*60)
    response = input("Show test instructions? (Y/n): ").strip().lower()
    if response != 'n':
        test_environment_setup()
    
    show_quick_setup_guide(shell_info)
    
    print(f"\n{Colors.GREEN}{Colors.BOLD} LLM/AI Setup completed!{Colors.END}")
    print(f"{Colors.CYAN}Next steps:{Colors.END}")
    print(f"1. Run shell script: {Colors.YELLOW}.\\apiscan_env.ps1{Colors.END} (PowerShell)")
    print(f"2. Test setup: {Colors.YELLOW}python test_env.py{Colors.END}")
    print(f"3. Run APISCAN: {Colors.YELLOW}python apiscan.py --api11 --target https://example.com{Colors.END}")
    
    if shell_info["os"] == "windows":
        print(f"\n{Colors.YELLOW} Windows tips:{Colors.END}")
        print(f" PowerShell: {Colors.YELLOW}Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser{Colors.END}")
    
    if "ollama" in providers_config:
        print(f"\n{Colors.CYAN} Ollama setup completed:{Colors.END}")
        print("  Check if Ollama is running:")
        print(f"  {Colors.YELLOW}curl http://localhost:11434/api/tags{Colors.END}")
        print("  Download a model:")
        print(f"  {Colors.YELLOW}ollama pull llama3{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Setup cancelled{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)