#!/usr/bin/python2.7

import sys
import requests
import socket
import logging
import getpass
import urllib2

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

###############################################################################

def main() :

    netlibre = NetlibRe()

    #register("test_autonetlibre","test")
    netlibre.login("test_autonetlibre","test")
    netlibre.addDomain  ("testauto2")
    netlibre.addRecord  ("testauto2", "A", "@", "3600",       "123.234.123.234")
    netlibre.addMXRecord("testauto2",      "@", "900",  "10", "123.234.123.234")

###############################################################################

def domainIsAlreadyUsed(name) :

    # FIXME
    # Not sure if it adress all cases ...
    # Could a domain be registered but with no A record, maybe that would not
    # be caught properly ... ?

    try :
        socket.gethostbyname(name)
        return True
    except Exception:
        return False

###############################################################################

def internetIsOn():

    reference = "91.198.174.192" # Wikipedia.org

    try:
        response=urllib2.urlopen('http://'+reference+'/',timeout=1)
        return True
    except urllib2.URLError as err:
        pass
    return False

###############################################################################

def chooseSubdomains() :

    input_ = raw_input("Choose subdomains, separated by commas"+
                       "(e.g. \"www,blog\"): ")

    subdomains = input_.replace(' ', ',').split(',')

    while '' in subdomains :
        subdomains.remove('')

###############################################################################

def chooseCredentials() :

    login     = raw_input("Choose a username: ")
    pw        = getpass.getpass(prompt="Choose a password: ")
    pwConfirm = getpass.getpass(prompt="Confirm  password: ")

    if (pw != pwConfirm) :
        pass # FIXME / TODO : raise exception
    else :
        return (login, pw)

###############################################################################

def getGlobalIp() :

    # FIXME
    # Handle exceptions, in particular if not networking running

    return urlopen('http://ip.42.pl/raw').read()

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
            logger.error("L'enregistrement du pseudo '"+login+"' a echoue.")
            return False
        else :
            logger.info("Vous avez enregistre le pseudo '"+login+"'.")
            return True

    #######################################################################

    def login(self, login, password) :

        logger.info("Tentative de login en tant que '"+login+"' ...")

        POSTdata = { 'login'     : login,
                     'password'  : password }

        # FIXME Karchnu ? Adding a / after login results in 404 (but it doesnt
        # in the register POST request ?)
        r = self.session.post("https://netlib.re/user/login",
                              data=POSTdata)

        if "Salut "+login+" !" not in r.text :
            logger.error("L'identification avec le pseudo '"+login
                         +"' a echoue.")
            return False
        else :
            logger.info("Connecte en tant que '"+login+"'.")
            return True

    #######################################################################

    def addDomain(self, name) :

        logger.info("Tentative d'ajout du domaine '"+name+".netlib.re' ...")

        POSTdata = { 'domain' : name,
                     'tld'    : ".netlib.re" }

        r = self.session.post("https://netlib.re/domain/add/",
                              data=POSTdata)

        if "details/"+name+".netlib.re" not in r.text :
            logger.error("L'ajout du domaine a echoue.")
            return False
        else :
            logger.info("Le domaine a ete ajoute.")
            return True

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
            logger.error("L'ajout de l'enregistrement a echoue.")
            return False
        else :
            logger.info("L'enregistrement a ete ajoute. (... Well, maybe ;).)")
            return True

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
            logger.error("L'ajout de l'enregistrement a echoue.")
            return False
        else :
            logger.info("L'enregistrement a ete ajoute. (... Well, maybe ;).)")
            return True

###############################################################################

main()

