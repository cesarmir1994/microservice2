from androguard.misc import AnalyzeAPK
import re
import os
import sys
from tld import get_tld
import ast
import json
from pythonjsonlogger import jsonlogger

#------------------------------------------------------------------
#                     LOG CONFIGURATION
#------------------------------------------------------------------
import logging as log
from pythonjsonlogger import jsonlogger

handler = None
logger = None


def init_logger(file):
    global handler, logger
    handler = log.FileHandler(file)
    format_str = '%(levelname)s%(asctime)s%(filename)s%(funcName)s%(lineno)d%(message)'
    formatter = jsonlogger.JsonFormatter(format_str)
    handler.setFormatter(formatter)
    logger = log.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(log.DEBUG)
    return logger


def stop_logger():
    logger.removeHandler(handler)
    handler.close()

logger = init_logger('logs.privapp.log')

#------------------------------------------------------------------
#                     FUNCTIONS CONFIGURATION
#------------------------------------------------------------------

# Test of input arguments
def InputArgs():
    logger.debug("Comprobate the input arguments")
    try:
        assert len(sys.argv)==2, 'ERROR: You do not ingress 2 arguments'
    except Exception as error:
        logger.error(error)
        exit(0)

# Obtain the reverse domain of the app_packaege
def reverse_domain(domain):
    """Reverses a domain name."""
    return '.'.join(reversed(domain.split('.')))

# OBtain the tokens of the package
def get_bag_of_package_domains(apk_package):
    try:
        logger.debug('we start to get the dominion of package apk')
        # Getting the "bag of domains" based on the package name
        apk = reverse_domain(apk_package.lower())
        res = get_tld(apk_package, fix_protocol=True, as_object=True, fail_silently=True)
        bag_of_package_domains = []
        if res is not None:
            bag_of_package_domains.append(res.domain)
            if res.subdomain != '':
                bag_of_package_domains.extend(res.subdomain.split('.'))
        else:
            bag_of_package_domains.extend(apk.split('.'))
        logger.debug('get the dominion of package apk successful')

        return [d for d in bag_of_package_domains if d not in ['com', 'org', 'net', 'int', 'edu', 'gob', 'www', 'sites']]
    except Exception as error:
        logger.error(error)

# Obtain the tokens of the url
def get_bag_of_url_domains(domain):
    try:
        logger.debug('we start to get the dominion of url ')
        # Getting "bag of domains" of targeted domains
        res = get_tld(domain, fix_protocol=True, as_object=True, fail_silently=True)
        bag_of_targeted_domains = []
        if res is not None:
            bag_of_targeted_domains.append(res.domain)
            if res.subdomain != '':
                bag_of_targeted_domains.extend(res.subdomain.split('.'))
        logger.debug('get the dominion of url successful')

        return [d for d in bag_of_targeted_domains if d not in ['www']]
    except Exception as error:
        logger.error(error)

# Obtain the urls of the APK
def get_urls_apk(path):
    try:
        logger.debug('Using Androguard')
        a, d, dx = AnalyzeAPK(path)
        logger.debug('modulus a, d, dx for ready')
        app_name = a.get_app_name()
        app_package = a.get_package()
        logger.debug('Filtering the urls of the obtained strings ')
        regex_result = dx.find_strings('http*')
        url_List = []
        for line in regex_result:
            url = line.get_value()
            url_List.append(str(url))

        logger.debug('get urls from apk were successful')
        return url_List, app_name, app_package
    except Exception as error:
        logger.error(error)

# Detects urls with key-words
def detect_urls_of_policy_privacy(url_List):
    try:
        logger.debug('beging to detect urls privacy')
        pp_List = []
        #loggin.debug('Se han obtenido un total de ' + str(len(url_List)) + ' urls')
        pattern = ['policy', 'privacy', 'politica', 'privacidad']
        for regex in pattern:
            reg = 'r' + regex
            patt = re.compile(reg)
            str_match = [x for x in url_List if re.search(regex, x)]
            pp_List.extend(str_match)

        if len(pp_List) != 0:
            logger.info('we found relationship to privacy urls')
            flg = False
        else:
            logger.info('we do not found relationship to privacy urls')
            flg = True
        
        logger.debug('The URLs detection process were successful')
        return pp_List, flg
    except Exception as error:
        logger.error(error)
#Inform if the url PP belongs to the app or to a third party
def inform_url_belong(urlList, package):
    try:
        logger.debug('Match tokens of url and package')
        package_tokens = get_bag_of_package_domains(package)
        app_list = []
        third_list = []
        for url in urlList:
            url_tokens = get_bag_of_url_domains(url)
            common_elements = set(package_tokens) & set(url_tokens)
            if len(common_elements) > 0:
                logger.info('There are domains in common')
                flg = True
            else:
                logger.info('There are no domains in common')
                flg = False

            if flg == True:
                logger.info('La url pertenece a la APP')
                app_list.append(url)
            else:
                logger.info('The url belongs to third parties')
                third_list.append(url)
        logger.debug('Match tokens were successful')
        return app_list, third_list

    except Exception as error:
        logger.error(error)


InputArgs()

path = sys.argv[1]

urlsList, appName, appPackage = get_urls_apk(path)

PPurlsList, flagEmpty = detect_urls_of_policy_privacy(urlsList)

if flagEmpty == True:
    logger.info('We do not find URLs of Privacy Policy')
else:
    appList, thirdList = inform_url_belong(PPurlsList, appPackage)

if len(appList)> 0:
    print('Las seiguientes urls pertenecen a la app')
    for url in appList:
        print(url)


if len(thirdList) > 0:
    print('Las urls que pertenecen a terceros son :')
    for url in thirdList:
        print(url)

logger = stop_logger()
