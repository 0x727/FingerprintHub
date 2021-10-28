import json
import os
import shutil
from pathlib import Path
from typing import Dict

import yaml
from git import Repo, Diff


class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)


def update_tags_yaml_format():
    with open("plugins/tags.yaml", "r") as y:
        tags = yaml.safe_load(y)
        tags_y = yaml.dump(tags, Dumper=MyDumper, sort_keys=False, allow_unicode=True,
                           default_flow_style=False, explicit_start=False, indent=2, width=2)
    with open("plugins/tags.yaml", "w") as y:
        y.write(tags_y)
    return tags


plugins_path_list = []

for site, site_list, file_list in os.walk("nuclei-templates"):
    for file_name in file_list:
        abs_filename = os.path.abspath(os.path.join(site, file_name))
        plugins_path_list.append(abs_filename)


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
        for file_path in plugins_path_list:
            if file_path.endswith(self.file_name):
                if Path(file_path).is_file():
                    shutil.rmtree(file_path)

    def renamed(self):
        print("renamed", self.file_name)
        for file_path in plugins_path_list:
            if file_path.endswith(self.file_name):
                if Path(file_path).is_file():
                    shutil.rmtree(file_path)
                    self.added('nuclei-templates/' + self.c_ins.rename_to)

    def modified(self):
        pass

    def copied(self):
        pass

    def run(self):
        if hasattr(self, self.mode):
            func = getattr(self, self.mode)
            func()


poc_dir_list = ['cves', 'cnvd', 'vulnerabilities', 'default-logins', 'exposures', 'miscellaneous']
tags_dict = update_tags_yaml_format()
fingerprint_list = []
for site, site_list, file_list in os.walk("fingerprint"):
    for file_name in file_list:
        fingerprint_list.append(file_name[:-len(Path(file_name).suffix)])


def find_nuclei_git_diff():
    repo = Repo('nuclei-templates')
    current_sha = repo.head.object.hexsha
    for c in repo.commit('HEAD~100').diff(current_sha):
        if not c.a_path.startswith('.') and c.a_path.endswith('.yaml') and Path(c.a_path).parts[0] in poc_dir_list:
            NucleiDiffGitMode(c_ins=c, g_tags_dict=tags_dict).run()


find_nuclei_git_diff()
#
# def tags_to_plugins_all():
#     for site, site_list, file_list in os.walk("nuclei-templates"):
#         for file_name in file_list:
#             abs_filename = os.path.abspath(os.path.join(site, file_name))
#             if len(Path(site).parts) > 1 and Path(site).parts[1] in poc_dir_list:
#                 if not file_name.startswith('.') and file_name.endswith('.yaml'):
#                     with open(abs_filename, 'r') as y:
#                         yaml_template = yaml.safe_load(y)
#                         try:
#                             tags = set(yaml_template.get('info')['tags'].split(','))
#                             for name, tags_list in tags_dict.items():
#                                 for tag in tags_list:
#                                     tags_set = tags.issuperset(tag)
#                                     if tags_set:
#                                         print(abs_filename)
#                                         to_file = os.path.join("plugins", name, file_name)
#                                         if not Path(to_file).parent.is_dir():
#                                             Path(to_file).parent.mkdir()
#                                         shutil.copy(abs_filename, to_file)
#                         except KeyError:
#                             pass
#
#
# tags_to_plugins_all()
