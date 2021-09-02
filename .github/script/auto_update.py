import json
import re
import string
from collections import OrderedDict
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


def valid_fingerprint_v2(rule):
    sorted_list = {'path': 0, 'request_method': 1, 'request_headers': 2, 'request_data': 3, 'status_code': 4,
                   'headers': 5, 'keyword': 6, 'priority': 7}
    fields = {'path': '/', 'status_code': 0, 'keyword': [], 'headers': {},
              'priority': 1, 'request_method': 'get', 'request_headers': {}, 'request_data': ''}
    for key in list(rule):
        if key not in fields:
            rule.pop(key)
    for key in fields:
        if key not in rule:
            rule[key] = fields[key]
        if key == 'request_data' and rule['request_data'] is None:
            rule[key] = fields[key]
    return dict(sorted(rule.items(), key=lambda t: sorted_list[t[0]]))


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
                    valid_rule['priority'] = y_dict.get('priority')
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
                max_priority = 0
                sorted_list = {'name': 0, 'priority': 1, 'fingerprint': 2}
                for fingerprint in fingerprint_rules_origin:
                    valid_rule = valid_fingerprint_v2(fingerprint)
                    priority = valid_rule.pop('priority')
                    if priority > max_priority:
                        max_priority = priority
                    fingerprint_rules.append(valid_rule)
                y_dict['fingerprint'] = fingerprint_rules
                y_dict['priority'] = max_priority
                new_y_dict = dict(sorted(y_dict.items(), key=lambda t: sorted_list[t[0]]))
                wfp_y = yaml.safe_dump(new_y_dict, sort_keys=False, allow_unicode=True, indent=2)
                with open(abs_filename, "w") as y:
                    y.write(wfp_y)


update_yaml("fingerprint")
fingerprint_json_generator_v2("fingerprint")
# fingerprint_json_generator("fingerprint")
