#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

import sys
import requests
import socket
import logging
import getpass
import urllib2
from optparse import OptionParser

#logging.basicConfig(level=logging.INFO)
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

###############################################################################

def main() :

    try :

        # Init stuff

        options = parseOptions()
        checkInternetIsOn()
        netlibre = NetlibRe()

        # Ask for credentials and login

        if (options.firstUse) :
            print "---------------------------------------------------------------"
            print " This script will help you create a netlib.re account.         "
            print " Please remember your credentials ! They will be needed if you "
            print " need to re-administrate your domains later.                   "
            print "---------------------------------------------------------------"
            (login, password) = chooseCredentials();
            netlibre.register(login, password)
        else :
            (login, password) = askForCredentials();

        netlibre.login(login, password)

        # Ask and validate domain
        domain = chooseDomain()

        if (domainIsAlreadyUsed(domain)) :
            raise Exception("This domain seems already used.")

        # Get global ip
        ip = getGlobalIp()

        # Adding domain
        print "Adding domain " + domain + ".netlib.re ..."
        netlibre.addDomain(domain)

        # Basic A record
        print "Adding basic A record"
        netlibre.addRecord  (domain, "A",     "@",      "3600", ip)

        # Mail stuff
        print "Adding mail stuff"
        netlibre.addRecord  (domain, "A",     "mail",   "3600", ip)
        netlibre.addMXRecord(domain,          "@",      "3600", "10", "mail")
        netlibre.addRecord  (domain, "TXT",   "@",      "3600", "\"v=spf1 a mx -all\"")

        # XMPP
        print "Adding XMPP stuff"
        netlibre.addRecord  (domain, "CNAME", "muc",    "3600", "@")
        netlibre.addRecord  (domain, "CNAME", "pubsub", "3600", "@")
        netlibre.addRecord  (domain, "CNAME", "vjud", "3600", "@")

    except Exception as e :

        print str(e)

###############################################################################

def parseOptions() :

    parser = OptionParser()

    parser.add_option("-f", "--first-use",
                      dest="firstUse",
                      default=False,
                      action="store_true",
                      help="Use this option if you do not already have a netlib.re account. This script will help you create one.")

    parser.add_option("-e", "--existing-account",
                      dest="existingAccount",
                      default=False,
                      action="store_true",
                      help="Use this option if you ALREADY have a netlib.re you want to use. Your credentials will be asked.")

    (options, args) = parser.parse_args()

    if (options.firstUse == options.existingAccount) :
        if (options.firstUse == False) :
            print "To use this script, you should use the option --first-use *or* --existing-account.\nSee --help."
        else :
            print "You can not use both --firstUse and --existingAccount at the same time."
        sys.exit(-1)

    return options

###############################################################################



def domainIsAlreadyUsed(name) :

    # FIXME
    # Not sure if it addresses all cases ...
    # Could a domain be registered but with no A record, maybe that would not
    # be caught properly ... ?

    try :
        socket.gethostbyname(name)
        return True
    except Exception:
        pass

    return False

###############################################################################

def checkInternetIsOn():

    logger.info("Checking there's a working internet connection ... ")

    reference = "91.198.174.192" # Wikipedia.org

    try:
        response=urllib2.urlopen('http://'+reference+'/',timeout=1)
        logger.info("Okay.")
        return
    except urllib2.URLError as err:
        pass

    logger.info("No working internet connection found.")
    raise Exception("No working internet connection found.")

###############################################################################

def chooseDomain() :

    domain = raw_input("Choose a netlib.re domain (e.g. put toto if you want toto.netlib.re): ")

    # FIXME : should allow more characters than just alphanumeric ?

    if (not domain.isalnum()) :
        raise Exception("Please use alphanumeric names for the domain.")

    return domain

###############################################################################

def chooseCredentials() :

    login     = raw_input("Choose a username: ")

    # FIXME : should allow more characters than just alphanumeric ?

    if (not login.isalnum()) :
        raise Exception("Please use alphanumeric usernames.")

    # FIXME : maybe a warning here if password security of netlib.re isn't so
    # strong, people shouldnt use a critical password ?

    pw        = getpass.getpass(prompt="Choose a password: ")
    pwConfirm = getpass.getpass(prompt="Confirm  password: ")

    if (pw != pwConfirm) :
        raise Exception("Passwords do not match !")
    else :
        return (login, pw)

###############################################################################

def askForCredentials() :

    login     = raw_input("Netlib.re username: ")
    pw        = getpass.getpass(prompt="Netlib.re password: ")

    return (login, pw)

###############################################################################

def getGlobalIp() :

    # FIXME
    # Handle exceptions, in particular if not networking running

    return urllib2.urlopen('http://ip.42.pl/raw').read()

###############################################################################

class NetlibRe :

    def __init__(self) :

        self.session = requests.Session()

        pass

    #######################################################################

    def register(self, login, password) :

        logger.info("Tentative d'enregistrement du pseudo '"+login+"' ...")

        POSTdata = { 'login'     : login,
                     'password'  : password,
                     'password2' : password }

        r = requests.post("https://netlib.re/user/add/",
                          data=POSTdata)

        if "Salut "+login+" !" not in r.text :
            raise Exception("L'enregistrement du pseudo '"+login+"' a échoué.")
        else :
            logger.info("Vous avez enregistré le pseudo '"+login+"'.")

    #######################################################################

    def login(self, login, password) :

        logger.info("Tentative de login en tant que '"+login+"' ...")

        POSTdata = { 'login'     : login,
                     'password'  : password }

        r = self.session.post("https://netlib.re/user/login",
                              data=POSTdata)

        if "Salut "+login+" !" not in r.text :
            raise Exception("L'identification avec le pseudo '"+login+"' a échoué.")
        else :
            logger.info("Connecte en tant que '"+login+"'.")

    #######################################################################

    def addDomain(self, name) :

        logger.info("Tentative d'ajout du domaine '"+name+".netlib.re' ...")

        POSTdata = { 'domain' : name,
                     'tld'    : ".netlib.re" }

        r = self.session.post("https://netlib.re/domain/add/",
                              data=POSTdata)

        if "details/"+name+".netlib.re" not in r.text :
            raise Exception("L'ajout du domaine a echoue.")
        else :
            logger.info("Le domaine a ete ajoute.")

    #######################################################################

    def addRecord(self, domain, type_, name, ttl, value) :

        logger.info("Tentative d'ajout d'un enregistrement de type A pour "
                    +domain+" : "+name+" <-> "+value)

        POSTdata = { 'type'  : type_,
                     'name'  : name,
                     'ttl'   : ttl,
                     'rdata' : value }

        r = self.session.post("https://netlib.re/domain/update/"
                              +domain+".netlib.re",
                              data=POSTdata)

        # FIXME
        # Better exception check here ? :/

        if "errmsg" in r.text :
            raise Exception("L'ajout de l'enregistrement a echoue.")
        else :
            logger.info("L'enregistrement a ete ajoute. (... Well, maybe ;).)")

    #######################################################################

    def addMXRecord(self, domain, name, ttl, priority, value) :

        logger.info("Tentative d'ajout d'un enregistrement MX pour "
                    +domain+" : "+name+" <-> "+value)

        POSTdata = { 'type'     : "MX",
                     'name'     : name,
                     'ttl'      : ttl,
                     'priority' : priority,
                     'rdata'    : value }

        r = self.session.post("https://netlib.re/domain/update/"
                              +domain+".netlib.re",
                              data=POSTdata)

        # FIXME
        # Better exception check here ? :/

        if "errmsg" in r.text :
            raise Exception("L'ajout de l'enregistrement a echoue.")
        else :
            logger.info("L'enregistrement a ete ajoute. (... Well, maybe ;).)")

###############################################################################

main()

