import os
import shutil
from pathlib import Path
from typing import Dict

import yaml
from git import Repo, Diff

poc_dir_list = ['cves', 'cnvd', 'vulnerabilities', 'default-logins', 'exposures', 'miscellaneous', "misconfiguration"]


class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)


def update_tags_yaml_format():
    with open("plugins/tags.yaml", "r") as y:
        tags = yaml.safe_load(y)
        tags_y = yaml.dump(tags, Dumper=MyDumper, sort_keys=True, allow_unicode=True,
                           default_flow_style=False, explicit_start=False, indent=2, width=2)
    with open("plugins/tags.yaml", "w") as y:
        y.write(tags_y)
    return tags


plugins_path_dict = {}
nuclei_path_dict = {}
fingerprint_path_dict = {}
tags_dict = update_tags_yaml_format()
for site, site_list, file_list in os.walk("plugins"):
    for file_name in file_list:
        plugins_abs_filename = os.path.abspath(os.path.join(site, file_name))
        if not file_name.startswith('.') and file_name.endswith('.yaml') and not file_name == "tags.yaml":
            plugins_path_dict.setdefault(file_name, plugins_abs_filename)

for site, site_list, file_list in os.walk("nuclei-templates"):
    for file_name in file_list:
        nuclei_abs_filename = os.path.abspath(os.path.join(site, file_name))
        if len(Path(site).parts) > 1 and Path(site).parts[1] in poc_dir_list:
            if not file_name.startswith('.') and file_name.endswith('.yaml'):
                nuclei_path_dict.setdefault(file_name, nuclei_abs_filename)

for site, site_list, file_list in os.walk("web_fingerprint"):
    for file_name in file_list:
        fingerprint_path_dict.setdefault(file_name[:-len(Path(file_name).suffix)], file_name)


class NucleiDiffGitMode:
    def __init__(self, c_ins: Diff, g_tags_dict: Dict):
        self.c_ins = c_ins
        self.tags_dict = g_tags_dict
        self.mode_map = {"A": 'added', "C": 'added', "D": 'deleted', "R": 'renamed', "M": 'added', "T": 'changed'}
        self.mode = self.mode_map.get(c_ins.change_type)
        self.abs_filename = 'nuclei-templates/' + self.c_ins.a_path
        self.file_name = Path(self.abs_filename).name

    def added(self, add_abs_filename=None):
        if add_abs_filename is None:
            add_abs_filename = self.abs_filename
        else:
            print("added", add_abs_filename)
        with open(add_abs_filename, 'r') as y:
            yaml_template = yaml.safe_load(y)
            try:
                tags = set(yaml_template.get('info')['tags'].split(','))
                for name, tags_list in self.tags_dict.items():
                    for tag in tags_list:
                        tags_set = tags.issuperset(tag)
                        if tags_set:
                            to_file = os.path.join("plugins", name, self.file_name)
                            if not Path(to_file).parent.is_dir():
                                Path(to_file).parent.mkdir()
                            shutil.copy(add_abs_filename, to_file)
            except KeyError:
                pass

    def changed(self):
        pass

    def deleted(self):
        print("deleted", self.file_name)
        for file_path in plugins_path_dict.values():
            if file_path.endswith(self.file_name):
                if Path(file_path).exists():
                    os.unlink(file_path)

    def renamed(self):
        print("renamed", self.file_name)
        for file_path in plugins_path_dict.values():
            if file_path.endswith(self.file_name):
                if Path(file_path).exists():
                    os.unlink(file_path)
                    self.added('nuclei-templates/' + self.c_ins.rename_to)

    def modified(self):
        pass

    def copied(self):
        pass

    def run(self):
        if hasattr(self, self.mode):
            func = getattr(self, self.mode)
            func()


def tags_to_plugins_all():
    for nuclei_file_name, file_path in nuclei_path_dict.items():
        with open(file_path, 'r') as y:
            yaml_template = yaml.safe_load(y)
            try:
                tags = set(yaml_template.get('info')['tags'].split(','))
                is_match = False
                for name, tags_list in tags_dict.items():
                    for tag in tags_list:
                        tags_set = tags.issuperset(tag)
                        if tags_set:
                            to_file = os.path.join("plugins", name, nuclei_file_name)
                            if not Path(to_file).parent.is_dir():
                                Path(to_file).parent.mkdir()
                            shutil.copy(file_path, to_file)
                            is_match = True
                if not is_match:
                    print("未分类Tags：", tags, file_path)
            except KeyError:
                pass
    all_fingerprints = set(fingerprint_path_dict.keys())
    all_tags = set(tags_dict.keys())
    print(all_tags.difference(all_fingerprints))


if __name__ == '__main__':
    repo = Repo('nuclei-templates')
    current_sha = repo.head.object.hexsha
    for c in repo.commit('HEAD~99').diff(current_sha):
        if not c.a_path.startswith('.') and c.a_path.endswith('.yaml') and Path(c.a_path).parts[0] in poc_dir_list:
            NucleiDiffGitMode(c_ins=c, g_tags_dict=tags_dict).run()
    tags_to_plugins_all()
