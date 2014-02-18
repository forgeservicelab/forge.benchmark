#!/usr/bin/env python

# Script for measuring response time for redmine urls.
# It attempts to authenticate via html form which is it given on first GET.
# It should work generally for anything that forwards properly, and has
# "username" and "password" fields in the form.
#
# I tested it for CASino login and standard Redmine login
#
# Exmaple invocation:
# ./redmine.py -u tkarasek -b http://193.166.24.110:8080 \
#              -l /rb/master_backlog/digile -c 5


import os
import sys
import getpass
import argparse
import mechanize
import cookielib
import logging
import time
import prettytable

logger = logging.getLogger("mechanize")
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.DEBUG)


DESCRIPTION = "FORGE benchmark for services behind CAS"
REDMINE_URL = 'https://support.forgeservicelab.fi/redmine'

MEASURED_URLS = ['/rb/taskboards/50',
                 '/rb/master_backlog/digile']

def getUser():
    user = os.environ.get('USER')
    if user and user != 'root':
        print "Using username: %s" % user
    else:
        user = raw_input('Give username: ')
    return user

def getPassword(user):
    dot_file = os.path.join(os.environ['HOME'], '.ldappass')
    pw = None
    if os.path.isfile(dot_file):
        with open(dot_file) as f:
            pw = f.read().strip()
            print "Using password from %s" % dot_file
    if not pw:
        pw = getpass.getpass(
            prompt="Give password for username %s: " % user)
    return pw


def getAuthenticatedHandle(baseurl, cookiejar, user, password, debug=False):
    br = mechanize.Browser()

    if debug:
        br.set_debug_http(True)
        br.set_debug_responses(True)
        br.set_debug_redirects(True)

    br.set_cookiejar(cookiejar)
    br.set_handle_equiv(True)
    br.set_handle_redirect(True)
    br.set_handle_referer(True)
    br.set_handle_robots(False)
    br.addheaders = [
        ('User-agent', ('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) '
                        'Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')),
        ('Accept', ('text/html,application/xhtml+xml,application/xml;q=0.9,'
                    '*/*;q=0.8'))
    ]
    br.open(baseurl)
    br.select_form(nr=0)
    br.form['username'] = user
    br.form['password'] = password
    br.submit()
    return br


def measureGet(browser, url):
    start_time = time.time()
    print "Getting %s .." % url
    browser.open(url)
    d = time.time() - start_time
    print ".. took %.2f secs" % d
    return d

def printResults(l):
    x = prettytable.PrettyTable(['URL', 'avg time [sec]'])
    for r in l:
        x.add_row(r)
    print x



if __name__ == '__main__':
    parser = argparse.ArgumentParser(DESCRIPTION,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    help_count = 'how many times to measure timeout for each url'
    help_baseurl = 'base url, e.g. https://auth.forgeservicelab.fi'
    help_locations = ('locations to measure. full url is baseurl + locations. '
                      ' e.g. /sessions')

    parser.add_argument('-d','--debug', help='show debug output',
                        action='store_true')
    parser.add_argument('-u','--user', help='user for CAS')
    parser.add_argument('-t','--test', help='user for CAS',
                        action='store_true')

    parser.add_argument('-b','--baseurl', help=help_baseurl,
                        default=REDMINE_URL)
    parser.add_argument('-c','--count', help=help_count, default=2, type=int)
    parser.add_argument('-l','--locations', help=help_locations, nargs='+',
                        default=MEASURED_URLS)

    args = parser.parse_args()

    if args.test:
        printResults([['a', '1.3'], ['b', '1.5']])
        sys.exit(0)

    if args.user:
        print "Using the username from args: %s" % args.user
        user = args.user
    else:
        user = getUser()

    password = getPassword(user)

    cookiejar = cookielib.LWPCookieJar()

    print ('Trying to authenticate via html form with given username and '
           'password ..')

    browser = getAuthenticatedHandle(args.baseurl, cookiejar, user, password,
                                     args.debug)

    print ".. authenticated"

    res = []
    for l in args.locations:
        url = args.baseurl + l
        tmp = []
        for i in range(args.count):
            d = measureGet(browser, url)
            tmp.append(d)
        res.append([url,  "%.2f" % (sum(tmp) / float(len(tmp)))])

    printResults(res)


