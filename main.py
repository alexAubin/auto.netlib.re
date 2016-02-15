#!/usr/bin/python

import re 
import sys
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

###############################################################################

def main() :

    s = requests.Session()
    
    #register("test_autonetlibre","test")
    login(s,"test_autonetlibre","test")
    #addDomain(s,"testauto")
    addARecord(s, "testauto", "@", "3600", "123.234.123.234")
    addMXRecord(s, "testauto", "@", "900", "10", "123.234.123.234")
    

###############################################################################

def register(login, password) :
        
    logger.info("Tentative d'enregistrement du pseudo '"+login+"' ...")

    POSTdata = { 'login'     : login, 
                 'password'  : password,
                 'password2' : password }

    r = requests.post("https://netlib.re/user/add/", data=POSTdata)
    
    if "Salut "+login+" !" not in r.text :
        logger.error("L'enregistrement du pseudo '"+login+"' a echoue.")
        return False
    else :
        logger.info("Vous avez enregistre le pseudo '"+login+"'.")
        return True

###############################################################################

def login(s, login, password) :
        
    logger.info("Tentative de login en tant que '"+login+"' ...")

    POSTdata = { 'login'     : login, 
                 'password'  : password }

    # FIXME Karchnu ? Adding a / after login results in 404 (but it doesnt in
    # the register POST request ?)
    r = s.post("https://netlib.re/user/login", data=POSTdata)
   
    if "Salut "+login+" !" not in r.text :
        logger.error("L'identification avec le pseudo '"+login+"' a echoue.")
        return False
    else :
        logger.info("Connecte en tant que '"+login+"'.")
        return True

###############################################################################

def addDomain(s, name) :
    
    logger.info("Tentative d'ajout du domaine '"+name+".netlib.re' ...")
    
    POSTdata = { 'domain' : name,
                 'tld'    : ".netlib.re" }
    
    r = s.post("https://netlib.re/domain/add/", data=POSTdata)

    if "details/"+name+".netlib.re" not in r.text :
        logger.error("L'ajout du domaine a echoue.")
        return False
    else :
        logger.info("Le domaine a ete ajoute.")
        return True

###############################################################################

def addARecord(s, domain, name, ttl, value) :
    
    logger.info("Tentative d'ajout d'un enregistrement de type A pour "+domain+" : "+name+" <-> "+value)

    POSTdata = { 'type'  : "A",
                 'name'  : name,
                 'ttl'   : ttl,
                 'rdata' : value }

    r = s.post("https://netlib.re/domain/update/"+domain+".netlib.re", data=POSTdata)
 
    # FIXME : better exception check here ? :/
    if "errmsg" in r.text :
        logger.error("L'ajout de l'enregistrement a echoue.")
        return False
    else :
        logger.info("L'enregistrement a ete ajoute. (... Well, maybe ;).)")
        return True

###############################################################################

def addMXRecord(s, domain, name, ttl, priority, value) :
    
    logger.info("Tentative d'ajout d'un enregistrement MX pour "+domain+" : "+name+" <-> "+value)

    POSTdata = { 'type'     : "MX",
                 'name'     : name,
                 'ttl'      : ttl,
                 'priority' : priority,
                 'rdata'    : value }

    r = s.post("https://netlib.re/domain/update/"+domain+".netlib.re", data=POSTdata)

    # FIXME : better exception check here ? :/
    if "errmsg" in r.text :
        logger.error("L'ajout de l'enregistrement a echoue.")
        return False
    else :
        logger.info("L'enregistrement a ete ajoute. (... Well, maybe ;).)")
        return True

###############################################################################

main()

