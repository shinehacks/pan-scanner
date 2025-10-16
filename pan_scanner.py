import os
import re
import sys
import csv
import string
import concurrent.futures
from collections import namedtuple
import mmap

# --- Helper Function for Packaged Executables ---

def get_resource_path(relative_path):
    """
    Get the absolute path to a resource, works for dev and for PyInstaller.
    This is crucial for finding the .yaml config files when the script
    is bundled into a single executable file.
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # If not bundled, the base path is the directory of the script
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# --- Custom, Dependency-Free Configuration Loaders ---

def manual_parse_key_value(file_path):
    """
    A simple key-value parser for the scan_config.yaml file.
    Parses lines like 'key: value' and ignores comments.
    """
    config = {}
    config_file_path = get_resource_path(file_path)
    try:
        with open(config_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith('#') or ':' not in line:
                    continue
                key, value = line.split(':', 1)
                config[key.strip()] = value.strip().replace("'", "").replace('"', '')
    except Exception as e:
        print(f"Error manually parsing '{config_file_path}': {e}", file=sys.stderr)
    return config

def load_card_networks(config_path='bins.yaml'):
    """
    Loads card network regex patterns dependency-free.
    """
    final_networks = {}
    current_network = None
    config_file_path = get_resource_path(config_path)
    try:
        with open(config_file_path, 'r', encoding='utf-8', newline=None) as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line.startswith('#') or not stripped_line:
                    continue
                if not line.startswith((' ', '\t')) and stripped_line.endswith(':'):
                    current_network = stripped_line[:-1]
                    continue
                if current_network and 'regex:' in stripped_line:
                    try:
                        regex_pattern = stripped_line.split('regex:', 1)[1].strip().strip("'\"")
                        final_networks[current_network] = re.compile(regex_pattern)
                    except (re.error, IndexError):
                        print(f"Warning: Malformed regex for '{current_network}'", file=sys.stderr)
        if not final_networks:
            print("Error: No networks loaded from config.", file=sys.stderr)
            exit(1)
        print(f"[*] Loaded {len(final_networks)} network definitions from '{config_file_path}'.")
        return final_networks
    except FileNotFoundError:
        print(f"Error: Config file '{config_file_path}' not found.", file=sys.stderr)
        exit(1)
    except Exception as e:
        print(f"An unexpected error occurred loading the config: {e}", file=sys.stderr)
        exit(1)

# --- Static Configuration ---

KEYWORDS = {
    'card', 'credit', 'debit', 'cc', 'account', 'acct', 'pan', 'number',
    'num', 'expiry', 'exp', 'visa', 'mastercard', 'amex'
}

EXCLUDED_EXTENSIONS = {
    '.png', '.jpg', 'jpeg', '.gif', '.bmp', '.tiff', '.svg',
    '.mp3', '.wav', '.mp4', 'mov', '.avi', '.mkv',
    '.iso', '.img', '.exe', '.dll', '.so', '.o', '.a', '.pyc', '.class',
    '.jar', '.lock', '.db',
}

EXCLUDED_DIRECTORIES = {
    # For Windows, we exclude common system/program folders.
    # Note: These are checked as case-insensitive paths.
    'C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)',
    # For Linux/macOS
    '/System', '/private', '/dev', '/var', '/tmp', '/Applications',
    '/Library', '/cores', '/net', '/home'
}

CONTEXT_WINDOW = 30

Finding = namedtuple('Finding', ['file_path', 'line_number', 'masked_pan', 'network', 'confidence', 'context'])

# --- Core Logic ---

def luhn_check(card_number):
    try:
        digits = [int(d) for d in str(card_number)]
        checksum = sum(digits[-1::-2])
        for d in digits[-2::-2]:
            d *= 2
            if d > 9:
                d -= 9
            checksum += d
        return checksum % 10 == 0
    except (ValueError, TypeError):
        return False

def identify_card_network(pan, card_networks):
    for network, pattern in card_networks.items():
        if pattern.match(pan):
            return network
    return None

def mask_pan(pan):
    return f"{pan[:6]}{'*' * (len(pan) - 10)}{pan[-4:]}"

def get_finding_details(clean_pan, match, line, file_path_str, line_num, card_networks):
    start, end = match.span()
    pre_char = line[start-1] if start > 0 else ' '
    post_char = line[end] if end < len(line) else ' '
    if pre_char.isdigit() or post_char.isdigit():
        return None

    if luhn_check(clean_pan):
        network = identify_card_network(clean_pan, card_networks)
        if network:
            window_start = max(0, start - CONTEXT_WINDOW)
            window_end = min(len(line), end + CONTEXT_WINDOW)
            context_snippet = line[window_start:window_end].lower()
            confidence = "High" if any(keyword in context_snippet for keyword in KEYWORDS) else "Medium"
            masked = mask_pan(clean_pan)
            return Finding(file_path_str, line_num, masked, network, confidence, line.strip())
    return None

def process_line(line, file_path_str, line_num, card_networks):
    findings = []
    for match in re.finditer(r'(?:\d[ -]*?){13,19}', line):
        potential_pan = match.group(0)
        clean_pan = re.sub(r'\D', '', potential_pan)
        if 13 <= len(clean_pan) <= 19:
            finding = get_finding_details(clean_pan, match, line, file_path_str, line_num, card_networks)
            if finding:
                findings.append(finding)
    return findings

def is_likely_binary(file_path, block_size=4096):
    try:
        with open(file_path, 'rb') as f:
            return b'\0' in f.read(block_size)
    except (IOError, OSError):
        return True

def scan_file(file_path, card_networks):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                findings.extend(process_line(line, file_path, line_num, card_networks))
    except (IOError, OSError, ValueError):
        pass
    return findings

def process_path(path, card_networks, max_file_size_bytes, max_archive_size_bytes):
    lowered_path = path.lower()
    try:
        file_size = os.path.getsize(path)
    except (IOError, OSError):
        return []

    is_archive = lowered_path.endswith(('.zip', '.tar'))
    if is_archive:
        if max_archive_size_bytes > 0 and file_size > max_archive_size_bytes:
            return []
    elif max_file_size_bytes > 0 and file_size > max_file_size_bytes:
        return []

    if is_archive or any(lowered_path.endswith(ext) for ext in EXCLUDED_EXTENSIONS) or lowered_path.endswith('.yaml'):
        return []
    if is_likely_binary(path):
        return []
    
    return scan_file(path, card_networks)

# --- Main Execution ---

def log_permission_error(e):
    print(f"\n[!] PermissionError: Skipping directory '{e.filename}'.", file=sys.stderr)

def run_scan(output_path, card_config_path, workers, min_level, max_file_size_mb, max_archive_size_mb):
    CARD_NETWORKS = load_card_networks(card_config_path)
    max_file_size_bytes = max_file_size_mb * 1024 * 1024
    max_archive_size_bytes = max_archive_size_mb * 1024 * 1024

    # --- NEW: Get scan paths based on OS ---
    scan_paths = []
    if sys.platform == "win32":
        print("[*] Detected Windows OS. Finding all available drives...")
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                scan_paths.append(drive)
                print(f"    - Found drive: {drive}")
    else:
        print("[*] Detected Linux/macOS. Scanning from root '/'.")
        scan_paths.append('/')
    # --- END NEW ---

    print(f"[*] Minimum confidence for reporting: '{min_level}'")
    
    files_to_scan = []
    for path in scan_paths:
        print(f"[*] Indexing files in '{path}'...")
        for root, dirs, files in os.walk(path, topdown=True, onerror=log_permission_error):
            # Case-insensitive directory exclusion
            dirs[:] = [d for d in dirs if os.path.join(root, d).lower() not in (ex.lower() for ex in EXCLUDED_DIRECTORIES)]
            for file in files:
                files_to_scan.append(os.path.join(root, file))

    print(f"[*] Found {len(files_to_scan)} potential items to analyze.")
    all_findings = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_file = {
                executor.submit(process_path, f, CARD_NETWORKS, max_file_size_bytes, max_archive_size_bytes): f 
                for f in files_to_scan
            }
            for i, future in enumerate(concurrent.futures.as_completed(future_to_file)):
                print(f"\r[*] Progress: {i + 1}/{len(files_to_scan)} items scanned...", end="")
                try:
                    all_findings.extend(future.result())
                except Exception as exc:
                    print(f'\n[!] {future_to_file[future]} generated an exception: {exc}', file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user.")

    print("\n")
    
    filtered_findings = [f for f in all_findings if f.confidence == 'High'] if min_level == 'High' else all_findings

    unique_findings = []
    seen_masked_pans = set()
    for finding in filtered_findings:
        if finding.masked_pan not in seen_masked_pans:
            unique_findings.append(finding)
            seen_masked_pans.add(finding.masked_pan)

    if unique_findings:
        print(f"[*] Scan complete. Found {len(all_findings)} total potential PANs.")
        print(f"[*] Writing {len(unique_findings)} unique findings with '{min_level}' or higher confidence to '{output_path}'...")
        try:
            unique_findings.sort(key=lambda x: ('High', 'Medium').index(x.confidence))
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(Finding._fields)
                writer.writerows(unique_findings)
            print(f"[*] Report successfully created.")
        except IOError as e:
            print(f"Error: Could not write report to '{output_path}'. Reason: {e}", file=sys.stderr)
    else:
        print("[*] Scan complete. No PANs found meeting the specified confidence level.")

def main():
    config = manual_parse_key_value('scan_config.yaml')
    if not config:
        print("FATAL: 'scan_config.yaml' not found or is empty.", file=sys.stderr)
        exit(1)

    output_path = config.get('output_path', 'pan_report.csv')
    min_level = config.get('min_level', 'Medium')
    
    workers_config = config.get('workers', 'auto')
    workers = os.cpu_count() or 1 if workers_config == 'auto' else int(workers_config)
    
    max_file_size_mb = int(config.get('max_file_size_mb', 500))
    max_archive_size_mb = int(config.get('max_archive_size_mb', 100))

    run_scan(
        output_path=output_path,
        card_config_path='bins.yaml',
        workers=workers,
        min_level=min_level,
        max_file_size_mb=max_file_size_mb,
        max_archive_size_mb=max_archive_size_mb
    )
    print("\n[*] Process finished.")

if __name__ == "__main__":
    main()

