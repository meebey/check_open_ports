#!/usr/bin/env python
#
# open_check_ports is a Nagios check that checks open ports against a whitelist
#
# Copyright (C) 2016 Mirco Bauer <meebey@meeby.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import nagiosplugin
import subprocess
import lxml.objectify

class OpenPortsResource(nagiosplugin.Resource):
    @property
    def name(self):
        return self._name

    def __init__(self, name='OPEN PORTS'):
        self._name = name
        self.portscan_range = None
        self.allowed_ports = []
        self.target_host = None
        self.nmap_extra_args = None

        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.unknown_ports = []

    def probe(self):
        self.scan_ports()
        return [
            nagiosplugin.Metric('open_ports', self.open_ports, context='ports', min=0),
            #nagiosplugin.Metric('closed_ports_count', len(self.closed_ports), context='ports', min=0),
            #nagiosplugin.Metric('filtered_ports_count', len(self.filtered_ports), context='ports', min=0),
            nagiosplugin.Metric('unknown_ports_count', len(self.unknown_ports), min=0),
        ]

    def scan_ports(self):
        nmap_command = [
            'nmap', self.target_host,
            '-n', # don't resolve hosts
            '-r', # don't randomize port order
            '-dd', # increase debug level to list closed ports too
            '-p', self.portscan_range,
            '-oX', '-' # output as XML to stdout
        ]
        if self.nmap_extra_args:
            for arg in self.nmap_extra_args.split(' '):
                nmap_command.append(arg)
        # run nmap
        nmap_output = subprocess.check_output(nmap_command)
        xml_parser = lxml.objectify.makeparser(no_network=True)
        root_node = lxml.objectify.fromstring(nmap_output, xml_parser)
        host_node = root_node.host
        for port_node in host_node.ports.port:
            port_number = port_node.attrib.get("portid")
            port_state = port_node.state.attrib.get("state")
            if port_state == 'open':
                self.open_ports.append(port_number)
            elif port_state == 'filtered':
                self.filtered_ports.append(port_number)
            elif port_state == 'closed':
                self.closed_ports.append(port_number)
            else:
                self.unknown_ports.append(port_number)

class OpenPortsContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        open_ports_critical = []
        for port in resource.open_ports:
            if not port in resource.allowed_ports:
                open_ports_critical.append(port)

        if len(open_ports_critical) > 0:
            return nagiosplugin.Result(
                nagiosplugin.Critical,
                'open port(s) found: {}'.format(str.join(',', open_ports_critical))
            )
        else:
            return nagiosplugin.Result(nagiosplugin.Ok)

@nagiosplugin.guarded
def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-v', '--verbose', action='count', default=0)
    arg_parser.add_argument('-H', '--host', required=True, nargs=1)
    arg_parser.add_argument('-p', '--portscan-range', nargs=1,
                            metavar='PORT_RANGE', help='port range, e.g.: 1-1024')
    arg_parser.add_argument('-a', '--allowed-ports', nargs=1, default='',
                            metavar='PORTS', help='list of ports split by "," (comma)')
    arg_parser.add_argument('-n', '--nmap-extra-args', nargs=1)
    args = arg_parser.parse_args()
    checker = OpenPortsResource('PORT SECURITY SCANNER')
    checker.target_host = args.host[0]
    if args.portscan_range:
        checker.portscan_range = args.portscan_range[0]
    else:
        checker.portscan_range = '1-65535'
    if args.allowed_ports and len(args.allowed_ports) > 0:
        checker.allowed_ports = args.allowed_ports[0].split(',')
    if args.nmap_extra_args:
        checker.nmap_extra_args = args.nmap_extra_args[0]
    check = nagiosplugin.Check(
        checker,
        OpenPortsContext('ports'),
        nagiosplugin.ScalarContext('unknown_ports_count', critical='0:0'),
    )
    check.main(args.verbose, timeout=0)

if __name__ == '__main__':
    debugger = False
    if debugger:
        checker = OpenPortsResource()
        checker.target_host = "localhost"
        checker.portscan_range = "1-1024"
        checker.scan_ports()
    else:
        main()
