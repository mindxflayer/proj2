import os
import glob
import json
import re

# Define all regexes for finding secrets, matching the Chrome extension patterns
RULES = [
    {
        "name": "AWS Key",
        "pattern": re.compile(r'\b((?:AKIA|ASIA|AROA|AIPA|ANPA|APKA|AIZA)[A-Z0-9]{16})\b'),
        "priority": 1,
        "get_prefix_len": lambda m: 4
    },
    {
        "name": "Stripe Key",
        "pattern": re.compile(r'\b((?:sk_live_|sk_test_|pk_live_|pk_test_|rk_live_)[a-zA-Z0-9]{20,60})\b'),
        "priority": 1,
        "get_prefix_len": lambda m: 8
    },
    {
        "name": "SendGrid Key",
        "pattern": re.compile(r'\b(SG\.[a-zA-Z0-9_\-]{22,60}\.[a-zA-Z0-9_\-]{43,})\b'),
        "priority": 1,
        "get_prefix_len": lambda m: 3
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r'\b((?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,40})\b'),
        "priority": 1,
        "get_prefix_len": lambda m: 4
    },
    {
        "name": "Slack Token",
        "pattern": re.compile(r'\b(xox[bpase]-[a-zA-Z0-9\-]{10,100})\b'),
        "priority": 1,
        "get_prefix_len": lambda m: 4
    },
    {
        "name": "Twilio SID",
        "pattern": re.compile(r'\b(AC[a-fA-F0-9]{32})\b'),
        "priority": 1,
        "get_prefix_len": lambda m: 2
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(r'(\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})'),
        "priority": 1,
        "get_prefix_len": lambda m: 3
    },
    {
        "name": "Bearer Token",
        "pattern": re.compile(r'(?i)\bBearer\s+([a-zA-Z0-9_\-+\/=]{20,})'),
        "priority": 1,
        "get_prefix_len": lambda m: 0
    },
    {
        "name": "HTTP Basic Auth",
        "pattern": re.compile(r'(?i)\bAuthorization\s*:\s*Basic\s+([a-zA-Z0-9+\/=]{8,})'),
        "priority": 1,
        "get_prefix_len": lambda m: 0
    },
    {
        "name": "Database Connection String",
        "pattern": re.compile(r'(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlserver|mariadb|oracle|cockroachdb):\/\/[^\s"\'\n]{1,64}:([^\s"\'\n@]{1,128})@[^\s"\'\n]{4,}'),
        "priority": 1,
        "get_prefix_len": lambda m: 0
    },
    {
        "name": "DATABASE_URL String",
        "pattern": re.compile(r'(?i)\bDATABASE_URL\s*=\s*["\']?[a-z+]+:\/\/[^\s"\'\n]{1,64}:([^\s"\'\n@]{1,128})@[^\s"\'\n]{4,}'),
        "priority": 1,
        "get_prefix_len": lambda m: 0
    },
    {
        "name": "Credentials in URL",
        "pattern": re.compile(r'(?i)https?:\/\/[^:@\s"\'\n\r]{1,64}:([^@\s"\'\n\r]{1,128})@[a-zA-Z0-9.\-]{4,}'),
        "priority": 1,
        "get_prefix_len": lambda m: 0
    },
    {
        "name": "API Key (context-anchored)",
        "pattern": re.compile(r'(?i)(?:api[_\-]?key|api[_\-]?secret|access[_\-]?key|auth[_\-]?token|client[_\-]?secret|app[_\-]?secret)\s*[:=]\s*["\']?([a-zA-Z0-9_\-+\/=]{20,})["\']?'),
        "priority": 2,
        "get_prefix_len": lambda m: 0
    },
    {
        "name": "Password Assignment",
        "pattern": re.compile(r'(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["\']([^"\'\n\r]{4,})["\']'),
        "priority": 2,
        "get_prefix_len": lambda m: 0
    },
    {
        "name": "Secret Assignment",
        "pattern": re.compile(r'(?i)(?:secret|signing_?key|encryption_?key|master_?key|private_?key)\s*[:=]\s*["\']([^"\'\n\r]{8,})["\']'),
        "priority": 2,
        "get_prefix_len": lambda m: 0
    }
]

def neutralize_string(s, prefix_len=0):
    prefix = s[:prefix_len]
    suffix = s[prefix_len:]
    
    # Check if the suffix is purely hex (ignoring non-alphanumeric characters)
    alnum_chars = [c for c in suffix if c.isalnum()]
    is_pure_hex = len(alnum_chars) > 0 and all(c in '0123456789abcdefABCDEF' for c in alnum_chars)
    
    pattern = "FACE" if is_pure_hex else "FAKE"
    pattern_idx = 0
    
    result = []
    for char in suffix:
        if char.isalpha():
            pat_char = pattern[pattern_idx % len(pattern)]
            if char.islower():
                result.append(pat_char.lower())
            else:
                result.append(pat_char.upper())
            pattern_idx += 1
        elif char.isdigit():
            result.append("0")
        else:
            result.append(char)
            
    return prefix + "".join(result)

def find_matches_in_text(text):
    matches = []
    for rule in RULES:
        for m in rule["pattern"].finditer(text):
            secret_str = m.group(1)
            start = m.start(1)
            end = m.end(1)
            
            prefix_len = rule["get_prefix_len"](m)
            matches.append({
                "start": start,
                "end": end,
                "secret": secret_str,
                "prefix_len": prefix_len,
                "rule_name": rule["name"],
                "priority": rule["priority"]
            })
    return matches

def resolve_overlaps(matches):
    # Sort matches:
    # 1. priority (lower number = higher priority)
    # 2. length of secret descending
    # 3. start index ascending
    matches.sort(key=lambda x: (x["priority"], -(x["end"] - x["start"]), x["start"]))
    
    kept = []
    for m in matches:
        overlap = False
        for k in kept:
            if max(m["start"], k["start"]) < min(m["end"], k["end"]):
                overlap = True
                break
        if not overlap:
            kept.append(m)
            
    kept.sort(key=lambda x: x["start"])
    return kept

def replace_secrets_in_text(text, file_replacements_count, global_examples):
    matches = find_matches_in_text(text)
    resolved = resolve_overlaps(matches)
    
    new_text = text
    # Process from right to left to avoid offset issues
    for m in reversed(resolved):
        original = m["secret"]
        rule_name = m["rule_name"]
        prefix_len = m["prefix_len"]
        
        if rule_name == "Stripe Key":
            prefix = original[:prefix_len]
            neutralized = prefix + "NOTAREALKEY_FAKE_TESTING_ONLY"
        elif rule_name == "SendGrid Key":
            prefix = original[:prefix_len]
            neutralized = prefix + "NOTAREAL_FAKEKEY_FOR_TESTING_ONLY_DO_NOT_USE"
        elif rule_name == "Slack Token":
            prefix = original[:prefix_len]
            neutralized = prefix + "NOTAREALTOKEN_FAKE_TESTING_ONLY"
        else:
            neutralized = neutralize_string(original, prefix_len)
        
        if original != neutralized:
            start, end = m["start"], m["end"]
            new_text = new_text[:start] + neutralized + new_text[end:]
            file_replacements_count[0] += 1
            if not any(ex[0] == original for ex in global_examples):
                rule_count = sum(1 for ex in global_examples if ex[2] == rule_name)
                if rule_count < 1:
                    global_examples.append((original, neutralized, rule_name))
                
    return new_text

def neutralize_data(data, file_replacements_count, global_examples):
    if isinstance(data, dict):
        return {k: neutralize_data(v, file_replacements_count, global_examples) for k, v in data.items()}
    elif isinstance(data, list):
        return [neutralize_data(item, file_replacements_count, global_examples) for item in data]
    elif isinstance(data, str):
        return replace_secrets_in_text(data, file_replacements_count, global_examples)
    else:
        return data

def main():
    data_dir = os.path.dirname(os.path.abspath(__file__))
    json_files = glob.glob(os.path.join(data_dir, "*.json"))
    # Exclude train.json and test.json
    json_files = [f for f in json_files if os.path.basename(f) not in ["train.json", "test.json"]]
    json_files = sorted(json_files)
    
    global_examples = []
    
    print("Scanning and neutralizing secrets in JSON files...")
    print("-" * 60)
    
    for file_path in json_files:
        filename = os.path.basename(file_path)
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(f"Error parsing {filename}: {e}")
                continue
                
        file_replacements_count = [0]
        neutralized_data_obj = neutralize_data(data, file_replacements_count, global_examples)
        
        # Write back to original file
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(neutralized_data_obj, f, indent=2)
            
        print(f"{filename}: {file_replacements_count[0]} replacements made")
        
    print("-" * 60)
    print("Example Replacements:")
    if global_examples:
        for before, after, rule in global_examples[:10]:
            print(f"\n[{rule}]:")
            print(f"  Before: {before}")
            print(f"  After:  {after}")
    else:
        print("No replacements were made.")

if __name__ == "__main__":
    main()
