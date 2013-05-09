#!/usr/bin/env python

import argparse
import string
import re

class LogFilterException: pass

class Parser(object):
    def __init__(self):
        self.data = {'ips': {}, 'urls': {}, 'files': {}, 'file_base_paths': {}}

    def parse(self, name, ip_filter = None, status_filter = None, method_filter = None):
        logfile = file(name, 'r')

        line  = logfile.readline()

        if ip_filter != None:
            ip = ip_filter
        else:
            ip = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

        if status_filter != None:
            status = status_filter
        else:
            status = '[1-6]\d{2}'

        if status_filter != None:
            status = status_filter
        else:
            status = '[1-6]\d{2}'

        if method_filter != None:
            method = method_filter.upper()
        else:
            method = '\w+'

        regex = re.compile('^(' + ip + ')\s[^ \t]+\s[^ \t]+\s\[([^\]]+)\]\s"(' + method +') ([^"]+) (HTTP/[^"]+)"\s(' + status + ')\s(-|\d+)')
        regex2 = re.compile('\?.*')
        while line:
            match  = re.search(regex, line)

            if match:
                if match.group(1) in self.data['ips']:
                    self.data['ips'][match.group(1)] += 1
                else:
                    self.data['ips'][match.group(1)] = 1

                file_base_path = re.sub(regex2, '', match.group(4))
                if file_base_path in self.data['file_base_paths']:
                    self.data['file_base_paths'][file_base_path] += 1
                else:
                    self.data['file_base_paths'][file_base_path] = 1
                    
                if match.group(4) in self.data['files']:
                    self.data['files'][match.group(4)] += 1
                else:
                    self.data['files'][match.group(4)] = 1

                self.data['urls'][match.group(4)] = match.group(7)

            line = logfile.readline()

        return self.data

class CommandLineParser(object):
    def __init__(self):
        argparser = argparse.ArgumentParser()
        group     = argparser.add_mutually_exclusive_group()
        group.add_argument('-i', '--ips', help = 'List ips and request stats. Default', action = 'store_true')
        group.add_argument('-s', '--sizes', help = 'List requests by biggest sizes', action = 'store_true')
        group.add_argument('-f', '--files', help = 'List requests by frequency', action = 'store_true')
        group.add_argument('-b', '--file_base_paths', help = 'List requests by frequency', action = 'store_true')

        argparser.add_argument('--ip-filter', help = 'Filter by ip address')
        argparser.add_argument('--status-filter', help = 'Filter by response status')
        argparser.add_argument('--method-filter', help = 'Filter by request method')
        argparser.add_argument('-q', '--quiet', help = 'Suppress unimportant information', action = 'store_true')
        argparser.add_argument('log_file', help = 'Log file to parse')
        self.args = argparser.parse_args()

    def getIPFilter(self):
        if self.args.ip_filter:
            return self.args.ip_filter
        else:
            return None

    def getStatusFilter(self):
        if self.args.status_filter:
            return self.args.status_filter
        else:
            return None

    def getMethodFilter(self):
        if self.args.method_filter:
            return self.args.method_filter
        else:
            return None

    def getFilename(self):
        return self.args.log_file

    def runQuiet(self):
        return self.args.quiet

    def getAction(self):
        if self.args.ips:
            return 'ips'
        elif self.args.sizes:
            return 'sizes'
        elif self.args.files:
            return 'files'
        elif self.args.file_base_paths:
            return 'file_base_paths'
        else:
            return 'ips'

class Formatter(object):
    def formatFrequency(self, data):
        if len(data) == 0:
            print "No results found"
            exit(1)

        url_length = 0;

        for x in data:
            if len(x) > url_length:
                url_length = len(x)

        url_length = 80 if url_length > 80 else url_length

        total = 0

        for x in data:
            total += data[x]

        data = sorted(data.items(), key = lambda (x, y): data[x], reverse = True)

        for (x, y) in data:
            print string.ljust(x, url_length) if len(x) < url_length else (x[- url_length:]), string.ljust(str(y), 5), "%.2f%%" % (1.0 * y / total * 100)

    def formatSizes(self, data):
        if len(data) == 0:
            print "No results found"
            exit(1)

        url_length = size_length = 0;

        for x in data:
            if len(x) > url_length:
                url_length = len(x)
            if len(data[x]) > size_length:
                size_length = len(data[x])

        url_length = 80 if url_length > 80 else url_length

        data = sorted(data.items(), key = lambda (x, y): data[x], cmp = self.compareSizes, reverse = True)

        for (x, y) in data:
            print '%s: %s' % (('...' + x[-url_length + 3:]) if len(x) > url_length else string.ljust(x, url_length), string.rjust(str(y), size_length))

    def compareSizes(self, a, b):
        if a == '-' and b == '-':
            return 0
        elif a == '-':
            return -1
        elif b == '-':
            return 1
        else:
            return int(a) - int(b)


class Controller(object):
    version = "0.1"

    def __init__(self):
        self.parser    = Parser()
        self.formatter = Formatter()
        self.command_line_parser = CommandLineParser()

    def echoInfo(self):
        print """Simple access log parser
Version: VERSION
""".replace('VERSION', self.version)

    def run(self):
        if not self.command_line_parser.getIPFilter():
            self.echoInfo()

        data = self.parser.parse(
            self.command_line_parser.getFilename(),
            self.command_line_parser.getIPFilter(),
            self.command_line_parser.getStatusFilter(),
            self.command_line_parser.getMethodFilter()
        )

        action = self.command_line_parser.getAction()

        if action == 'ips':
            self.formatter.formatFrequency(data['ips'])

        elif action == 'sizes':
            self.formatter.formatSizes(data['urls'])

        elif action == 'files':
            self.formatter.formatFrequency(data['files'])

        elif action == 'file_base_paths':
            self.formatter.formatFrequency(data['file_base_paths'])

        else:
            print "%s has not been implemented yet" % action
            exit(1)

controller = Controller();
controller.run()
