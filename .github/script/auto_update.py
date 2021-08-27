import json
import re
import string
from operator import itemgetter
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


def valid_fingerprint_v2(rule):
    fields = {'path': '/', 'status_code': 0, 'keyword': [], 'headers': {}, 'favicon_hash': [],
              'priority': 1, 'request_method': 'get', 'request_headers': {}, 'request_data': ''}
    for key in list(rule):
        if key not in fields:
            rule.pop(key)
    for key in fields:
        if key not in rule:
            rule[key] = fields[key]
        if key == 'request_data' and rule['request_data'] is None:
            rule[key] = fields[key]
    return rule


def fingerprint_json_generator(path):
    fingerprint_all_dict = {}
    for site, site_list, file_list in os.walk(path):
        for file_name in file_list:
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
    for k in list(fingerprint_all_dict):
        unsorted_fingerprint = fingerprint_all_dict[k]
        sorted_fingerprint = sorted(unsorted_fingerprint, key=itemgetter('name'))
        fingerprint_all_dict[k] = sorted_fingerprint
    web_fingerprint = dict(sorted(fingerprint_all_dict.items()))
    with open("web_fingerprint.json", 'w') as wfp:
        json.dump(web_fingerprint, wfp)
    return web_fingerprint


def fingerprint_json_generator_v2(path):
    fingerprint_all_list = []
    for site, site_list, file_list in os.walk(path):
        for file_name in file_list:
            abs_filename = os.path.abspath(os.path.join(site, file_name))
            with open(abs_filename) as y:
                y_dict = yaml.safe_load(y)
                fingerprint_rules_origin = y_dict.get('fingerprint', [])
                for fingerprint in fingerprint_rules_origin:
                    valid_rule = valid_fingerprint_v2(fingerprint)
                    valid_rule['name'] = y_dict.get('name')
                    fingerprint_all_list.append(valid_rule)
    web_fingerprint = sorted(fingerprint_all_list, key=itemgetter('name'))
    with open("web_fingerprint_v2.json", 'w') as wfp:
        json.dump(web_fingerprint, wfp)
    return web_fingerprint


def update_yaml(path):
    for site, site_list, file_list in os.walk(path):
        for file_name in file_list:
            abs_filename = os.path.abspath(os.path.join(site, file_name))
            fingerprint_rules = []
            with open(abs_filename) as y:
                y_dict = yaml.safe_load(y)
                fingerprint_rules_origin = y_dict.get('fingerprint', [])
                for fingerprint in fingerprint_rules_origin:
                    valid_rule = valid_fingerprint_v2(fingerprint)
                    fingerprint_rules.append(valid_rule)
                y_dict['fingerprint'] = fingerprint_rules
                wfp_y = yaml.safe_dump(y_dict, sort_keys=False, allow_unicode=True, indent=2)
                with open(abs_filename, "w") as y:
                    y.write(wfp_y)


update_yaml("fingerprint")
fingerprint_json_generator_v2("fingerprint")
# fingerprint_json_generator("fingerprint")
