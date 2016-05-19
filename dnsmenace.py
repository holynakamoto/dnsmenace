#!/usr/bin/env python
"""dnsmenace - Global DNS query by country
        Usage:
            dnsmenace.py (--dns) [--country=<country>]
            dnsmenace.py (--get)
            dnsmenace.py (--geta)
            dnsmenace.py (-h | --help)
            dnsmenace.py (-v | --version)
        Options:
                -h --help     Show this screen.
                -v --version  Show version.
                --dns         What country to query for
                --country=<country>    Two Letter Country Code
"""

from docopt import docopt
import urllib
import json
import dns.resolver
from iso3166 import countries

def get_resolv():
    url = 'http://public-dns.info/nameserver/%s.json' % (args['--country'])
    response = urllib.urlopen(url)
    data = json.loads(response.read())
    fqdn = raw_input("FQDN: ")
    number = input("Enter the number of nameservers: ")
    dns1 = []
    ns1 = []

    for item in data:
        dns1.append(item['ip'])
    for item in data:
        ns1.append(item['name'])

    for name in ns1[:number]:
        if not name:
            pass
        else:
            print "nameserver =", name
            print "=============================="

    for ip in dns1[:number]:
        myResolver = dns.resolver.Resolver()
        myResolver.nameservers = dns1
        myAnswers0 = myResolver.query(fqdn, "A")
        for rdata in myAnswers0:
            print fqdn, rdata 
            print "=============================="

def get_country():
    name = raw_input("What country: ")
    print countries.get(name)[:number]

def get_all():
    for c in countries:
       print c

if __name__ == '__main__':
    args = docopt(__doc__, version='dnsmenace 1.0.0')
    if args['--dns']:
        get_resolv()
    if args['--get']:
        get_country()
    if args['--geta']:
        get_all()

