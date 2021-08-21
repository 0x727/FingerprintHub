import json
import re
import string
from pathlib import Path
import yaml
import os

allow_string = string.digits + string.ascii_letters + '-_ '


def is_allow_string(char):
    if u'\u4e00' <= char <= u'\u9fff' or char in allow_string:
        return True
    return False


def replace_name(name):
    name = name.strip()
    name = name.replace('（', '(').replace('）', ')')
    name = re.sub(r"[(\[].*?[)\]]", "", name)
    name = ''.join([s for s in name if is_allow_string(s)])
    name = name.strip().replace(' ', '-').replace('--', '-').replace('--', '-')
    return name.lower()


def valid_fingerprint(rule):
    fields = ['name', 'path', 'status_code', 'keyword', 'headers', 'favicon_hash', 'priority']
    if all([key in rule for key in fields]):
        for key in list(rule):
            if key not in fields:
                rule.pop(key)
        return rule
    else:
        print("字段不完全", rule)
        return None


def fingerprint_json_generator(path):
    fingerprint_all_dict = {}
    for site, site_list, file_list in os.walk(path):
        for file_name in file_list:
            print(file_name)
            abs_filename = os.path.abspath(os.path.join(site, file_name))
            with open(abs_filename) as y:
                y_dict = yaml.safe_load(y)
                name = replace_name(y_dict.get('name', ''))
                fingerprint_rules = y_dict.get('fingerprint', [])
                for rule in fingerprint_rules:
                    rule['name'] = name
                    valid_rule = valid_fingerprint(rule)
                    if valid_rule:
                        path = rule.pop('path')
                        if path not in fingerprint_all_dict:
                            fingerprint_all_dict.setdefault(path, [valid_rule])
                        else:
                            rules = fingerprint_all_dict.get(path, [])
                            if valid_rule not in rules:
                                rules.append(valid_rule)
                                fingerprint_all_dict[path] = rules
    web_fingerprint = dict(sorted(fingerprint_all_dict.items()))
    with open("web_fingerprint.json", 'w') as wfp:
        json.dump(web_fingerprint, wfp)
    return web_fingerprint


fingerprint_json_generator("fingerprint")
