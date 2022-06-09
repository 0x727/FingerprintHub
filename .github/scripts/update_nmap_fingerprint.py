#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os

import yaml


class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)


class ServiceScanException(Exception):
    pass


class ServiceProbe(object):
    """
    解析 nmap - service - probes 文件
    """

    def __init__(self):
        base_path = os.path.dirname(os.path.realpath(__file__))
        self.probe_raw_filename = os.path.join(base_path, "nmap-service-probes")
        self.probe_json_filename = os.path.join(base_path, "../", "../", 'nmap_service_probes.json')

    def parse(self):
        r = self.get_probe_raw_file()
        sorted_list = {"protocol": 0, "directive_name": 1, "directive_str": 2, "rarity": 3, "ports": 4, "fallback": 5,
                       "matches": 6}
        for nmap_fingerprint in r:
            sorted_nmap_fingerprint = {k: v for k, v in
                                       sorted(nmap_fingerprint.items(), key=lambda item: sorted_list[item[0]])}

            nmap_fingerprint_yaml = yaml.dump(sorted_nmap_fingerprint, Dumper=MyDumper, sort_keys=False,
                                              allow_unicode=True,
                                              default_flow_style=False, explicit_start=False, indent=2, width=2)
            save_path = os.path.join("service_fingerprint", nmap_fingerprint.get("directive_name") + ".yaml")
            with open(save_path, "w") as y:
                y.write(nmap_fingerprint_yaml)
        json.dump(r, open(self.probe_json_filename, 'w'), indent=2, ensure_ascii=False)
        return r

    def get_probe_raw_file(self):
        if not os.path.exists(self.probe_raw_filename):
            raise ServiceScanException('Fail to open file %s' % self.probe_raw_filename)

        lines = []
        with open(self.probe_raw_filename, 'r', encoding="utf-8") as fp:
            for line in fp:
                # 不去读取注释
                if line.startswith('\n') or line.startswith('#'):
                    continue
                lines.append(line)
        self.isvalid_nmap_service_probe_file(lines)
        return self.parse_nmap_service_probes(lines)

    @staticmethod
    def isvalid_nmap_service_probe_file(lines):
        """
        确认nmap probe是否正确
        :param lines:
        :return:
        """
        if not lines:
            raise ServiceScanException("Failed to read file")
        c = 0
        for line in lines:
            if line.startswith("Exclude "):
                c += 1
            if c > 1:
                raise ServiceScanException("Only 1 Exclude allowed")
            line_l = lines[0]
            if not (line_l.startswith("Exclude ") or line_l.startswith("Probe ")):
                raise ServiceScanException("Parse error on nmap-service-probes file")

    def parse_nmap_service_probes(self, lines):
        """
        parse probes的文件
        :param lines:
        :return:
        """
        data = "".join(lines)
        probes_parts = data.split("\nProbe ")
        _ = probes_parts.pop(0)
        if _.startswith("Exclude "):
            # g_exclude_directive = _
            pass
        # 根据Probe分割,循环读取service指纹
        return [
            self.parse_nmap_service_probe(probe_part)
            for probe_part in probes_parts
        ]

    def parse_nmap_service_probe(self, data):
        lines = data.split("\n")

        probe_str = lines.pop(0)
        probe = self.get_probe(probe_str)

        matches = []

        for line in lines:
            if line.startswith("match "):
                match = self.get_match(line)
                if match not in matches:
                    matches.append(match)
            elif line.startswith("ports "):
                probe["ports"] = self.get_ports(line)

            elif line.startswith("ssl_ports "):
                probe["ssl_ports"] = self.get_ssl_ports(line)

            elif line.startswith("total_wait_ms "):
                probe["total_wait_ms"] = self.get_total_wait_ms(line)

            elif line.startswith("tcp_wrapped_ms "):
                probe["tcp_wrapped_ms"] = self.get_tcp_wrapped_ms(line)

            elif line.startswith("rarity "):
                probe["rarity"] = self.get_rarity(line)

            elif line.startswith("fallback "):
                probe["fallback"] = self.get_fallback(line)

        probe['matches'] = matches

        return probe

    #####################################################
    # 解析
    @staticmethod
    def parse_directive_syntax(data):
        """
        获取语法数据
        <directive_name><blank_space><flag><delimiter><directive_str><flag>
        :param data:
        :return:
        """
        if data.count(" ") <= 0:
            raise ServiceScanException("nmap-service-probes - error directive format")

        blank_index = data.index(" ")
        directive_name = data[:blank_index]
        __blank_space = data[blank_index: blank_index + 1]
        flag = data[blank_index + 1: blank_index + 2]
        delimiter = data[blank_index + 2: blank_index + 3]
        directive_str = data[blank_index + 3:]

        directive = {
            "directive_name": directive_name,
            "flag": flag,
            "delimiter": delimiter,
            "directive_str": directive_str
        }
        return directive

    def get_probe(self, data):
        """
        得到probe格式
        Format: [Proto][probe_name][blank_space][__host_port_queue][delimiter][probe_string]
        NULL __host_port_queue||
        GenericLines __host_port_queue|\r\n\r\n|
        :param data:
        :return:
        """
        proto = data[:4]
        other = data[4:]
        if proto not in ["TCP ", "UDP "]:
            raise ServiceScanException("Probe <protocol> must be either TCP or UDP")

        if not (other and other[0].isalpha()):
            raise ServiceScanException("nmap-service-probes - bad probe name")

        directive = self.parse_directive_syntax(other)

        directive_name = directive.get("directive_name")
        directive_str, _ = directive.get("directive_str").split(directive.get("delimiter"), 1)

        probe = {
            "protocol": proto.strip(),
            "directive_name": directive_name,
            "directive_str": directive_str
        }

        return probe

    def get_match(self, data):
        """
        Syntax: match <service> <pattern> [<version_info>]
        :param data:
        :return:
        """
        match_text = data[len("match") + 1:]
        directive = self.parse_directive_syntax(match_text)

        pattern, version_info = directive.get("directive_str").split(
            directive.get("delimiter"), 1
        )
        record = {
            "service": directive.get("directive_name"),
            "pattern": pattern,
            "version_info": version_info
        }
        return record

    @staticmethod
    def get_ports(data):
        """

        :param data:
        :return:
        """
        ports = data[len("ports") + 1:]
        ports_string_list = ports.split(",")
        ports_ranges = []
        for ports_string in ports_string_list:
            if "-" in ports_string:
                start, end = ports_string.split("-")
                ports_ranges.extend(range(int(start), int(end)))
            else:
                ports_ranges.append(int(ports_string))
        return ports_ranges

    @staticmethod
    def get_ssl_ports(data):
        """

        :param data:
        :return:
        """
        ssl_ports = data[len("ssl_ports") + 1:]
        # record = {
        #     "ssl_ports": ssl_ports
        # }
        return ssl_ports

    @staticmethod
    def get_total_wait_ms(data):
        total_wait_ms = data[len("total_wait_ms") + 1:]
        # record = {
        #     "total_wait_ms": total_wait_ms
        # }
        return total_wait_ms

    @staticmethod
    def get_tcp_wrapped_ms(data):
        # Syntax: tcp_wrapped_ms <milliseconds>
        tcp_wrapped_ms = data[len("tcp_wrapped_ms") + 1:]
        # record = {
        #     "tcp_wrapped_ms": tcp_wrapped_ms
        # }
        return tcp_wrapped_ms

    @staticmethod
    def get_rarity(data):
        # Syntax: rarity <value between 1 and 9>
        # Syntax: tcp_wrapped_ms <milliseconds>
        rarity = int(data[len("rarity") + 1:])
        # record = {
        #     "rarity": rarity
        # }
        return rarity

    @staticmethod
    def get_fallback(data):
        fallback = data[len("fallback") + 1:]
        # record = {
        #     "fallback": fallback
        # }
        return fallback


def update_nmap_fingerprint(path):
    nmap_fingerprint_json = []
    for site, site_list, file_list in os.walk(path):
        for file_name in file_list:
            abs_filename = os.path.abspath(os.path.join(site, file_name))
            if abs_filename.endswith(".yaml"):
                with open(abs_filename) as n:
                    n_dict = yaml.safe_load(n)
                    nmap_fingerprint_json.append(n_dict)
    nmap_fingerprint_json_sorted = sorted(nmap_fingerprint_json, key=lambda t: t.get("rarity", 0))
    with open("nmap_service_probes.json", "w") as nsp:
        json.dump(nmap_fingerprint_json_sorted, nsp, indent=2, ensure_ascii=False)


# https://svn.nmap.org/nmap/nmap-service-probes
if __name__ == '__main__':
    update_nmap_fingerprint("service_fingerprint")
# service_probe = ServiceProbe()
# service_probe.parse()
