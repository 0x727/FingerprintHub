import json
import re
import string
from operator import itemgetter
from pathlib import Path

import yaml
import os

try:
    from git import Repo, Diff
except ModuleNotFoundError:
    pass

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


class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)


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


def valid_fingerprint_v3(rule):
    sorted_list = {'path': 0, 'request_method': 1, 'request_headers': 2, 'request_data': 3, 'status_code': 4,
                   'headers': 5, 'keyword': 6, 'favicon_hash': 7, 'priority': 8}
    fields = {'path': '/', 'status_code': 0, 'keyword': [], 'headers': {}, 'favicon_hash': [],
              'priority': 1, 'request_method': 'get', 'request_headers': {}, 'request_data': ''}
    for key in list(rule):
        if key not in fields:
            rule.pop(key)
    headers = rule.get("headers", {})  # 转字符串
    for k in list(headers):
        headers[k] = str(headers[k])
    rule["headers"] = headers
    for key in fields:
        if key not in rule:
            rule[key] = fields[key]
        if key == 'request_data' and rule['request_data'] is None:
            rule[key] = fields[key]
    return dict(sorted(rule.items(), key=lambda t: sorted_list[t[0]]))


def fingerprint_json_generator(path):
    fingerprint_all_v2_list = []
    fingerprint_all_v3_list = []
    nuclei_tags_dict = {}
    for site, site_list, file_list in os.walk(path):
        for file_name in file_list:
            abs_filename = os.path.abspath(os.path.join(site, file_name))
            with open(abs_filename) as y:
                y_dict = yaml.safe_load(y)
                fingerprint_rules_origin = y_dict.get('fingerprint', [])
                for fingerprint in fingerprint_rules_origin:
                    valid_rule_v3 = valid_fingerprint_v3(fingerprint)
                    valid_rule_v3['name'] = y_dict.get('name')
                    valid_rule_v3['priority'] = y_dict.get('priority')
                    if y_dict.get("nuclei_tags") != [[]]:
                        nuclei_tags_dict.setdefault(y_dict.get("name"),
                                                    y_dict.get("nuclei_tags", [[]]))
                    valid_rule_v2 = valid_fingerprint_v2(fingerprint)
                    valid_rule_v2['name'] = y_dict.get('name')
                    valid_rule_v2['priority'] = y_dict.get('priority')
                    fingerprint_all_v3_list.append(valid_rule_v3)
                    fingerprint_all_v2_list.append(valid_rule_v2)
    web_fingerprint_v2 = sorted(fingerprint_all_v2_list, key=itemgetter('name'))
    web_fingerprint_v3 = sorted(fingerprint_all_v3_list, key=itemgetter('name'))
    with open("web_fingerprint_v2.json", 'w') as wfp:
        json.dump(web_fingerprint_v2, wfp, indent=2, ensure_ascii=False)
    with open("web_fingerprint_v3.json", 'w') as wfp:
        json.dump(web_fingerprint_v3, wfp, indent=2, ensure_ascii=False)
    with open("plugins/tags.yaml", "w") as y:
        tags_y = yaml.dump(nuclei_tags_dict, Dumper=MyDumper, sort_keys=True, allow_unicode=True,
                           default_flow_style=False, explicit_start=False, indent=2, width=2)
        y.write(tags_y)
    return web_fingerprint_v3


def update_yaml(path):
    for site, site_list, file_list in os.walk(path):
        for file_name in file_list:
            abs_filename = os.path.abspath(os.path.join(site, file_name))
            format_yaml(abs_filename)


def format_yaml(format_path):
    suffix = Path(format_path).suffix
    suffix_file_name = Path(format_path).name[0:-len(suffix)]
    if suffix_file_name != replace_name(suffix_file_name):
        suffix_file_name = replace_name(suffix_file_name)
        new_path = Path(format_path).with_name(suffix_file_name).with_suffix(suffix)
        Path(format_path).rename(new_path)
    fingerprint_rules = []
    with open(format_path) as y:
        y_dict = yaml.safe_load(y)
        fingerprint_rules_origin = y_dict.get('fingerprint', [])
        max_priority = 0
        sorted_list = {'name': 0, 'priority': 1, 'nuclei_tags': 2, 'fingerprint': 3}
        for fingerprint in fingerprint_rules_origin:
            fingerprint['priority'] = y_dict.get('priority')
            valid_rule = valid_fingerprint_v3(fingerprint)
            priority = valid_rule.pop('priority')
            if priority > max_priority:
                max_priority = priority
            fingerprint_rules.append(valid_rule)
        y_dict['fingerprint'] = fingerprint_rules
        y_dict['priority'] = max_priority
        y_dict['name'] = suffix_file_name
        y_dict.setdefault('nuclei_tags', [[]])
        new_y_dict = dict(sorted(y_dict.items(), key=lambda t: sorted_list[t[0]]))
        wfp_y = yaml.dump(new_y_dict, Dumper=MyDumper, sort_keys=False, allow_unicode=True,
                          default_flow_style=False, explicit_start=False, indent=2, width=2)
        with open(format_path, "w") as y:
            y.write(wfp_y)


def no_git():
    for site, site_list, file_list in os.walk("web_fingerprint"):
        for file_name in file_list:
            plugins_abs_filename = os.path.abspath(os.path.join(site, file_name))
            if not file_name.startswith('.') and file_name.endswith('.yaml') and not file_name == "tags.yaml":
                format_yaml(plugins_abs_filename)
    fingerprint_json_generator("web_fingerprint")


if __name__ == '__main__':
    try:
        repo = Repo('./')
        current_sha = repo.head.object.hexsha
        poc_path_list = []
        is_change = False
        for c in repo.commit('HEAD~').diff(current_sha):
            if c.a_path.startswith('web_fingerprint/') and c.a_path.endswith('.yaml'):
                if Path(c.a_path).exists():
                    format_yaml(c.a_path)
                is_change = True
    except NameError:
        pass
    fingerprint_json_generator("web_fingerprint")
    if os.getenv("USER") == "kali-team":
        no_git()
