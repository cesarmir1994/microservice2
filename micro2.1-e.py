from androguard.misc import AnalyzeAPK
import re
import os
from tld import get_tld
import ast
import json
import subprocess
import logging as log
from pythonjsonlogger import jsonlogger
#------------------------------------------------------------------
#                     LOG CONFIGURATION
#------------------------------------------------------------------
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
    logger.setLevel(log.INFO)
    return logger

def stop_logger():
    logger.removeHandler(handler)
    handler.close()

logger = init_logger('logs.privapp.log')
#------------------------------------------------------------------
#                     FUNCTIONS CONFIGURATION
#------------------------------------------------------------------
# Obtain the reverse domain of the app_packaege
def reverse_domain(domain):
    try:
        """Reverses a domain name."""
        return '.'.join(reversed(domain.split('.')))
    except Exception as e:
        reason = 'get_bag_of_targeted_domains unavailable'
        logger.error('bag of domains failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('The function was right')

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
    except Exception as e:
        reason = 'get_bag_of_package_domains unavailable'
        logger.error('bag of package failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('get the dominion of package apk successful')
        return [d for d in bag_of_package_domains if
                d not in ['com', 'org', 'net', 'int', 'edu', 'gob', 'www', 'sites']]
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
    except Exception as e:
        reason = 'get_bag_of_url_domains unavailable'
        logger.error('bag of url domains failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('get the dominion of the URL was successful')
        return [d for d in bag_of_targeted_domains if d not in ['www']]

# Obtain the urls of the APK
def get_urls_apk(path):
    try:
        logger.debug('Using Androguard')
        a, d, dx = AnalyzeAPK(path)
        logger.debug('modulus a, d, dx for ready')
        app_name = a.get_app_name()
        app_version = a.get_androidversion_name()
        app_package = a.get_package()
        logger.debug('Filtering the urls of the obtained strings ')
        regex_result = dx.find_strings('http*')
        url_List = []
        for line in regex_result:
            url = line.get_value()
            url_List.append(str(url))
    except Exception as e:
        reason = 'get_urls_apk unavailable'
        logger.error('get_urls_apk failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('get urls from apk were successful')
        return url_List, app_name, app_version, app_package

# Detects urls with key-words
def detect_urls_of_policy_privacy(url_List):
    try:
        logger.debug('beging to detect urls privacy')
        pp_List = []
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

    except Exception as e:
        reason = 'detect_urls_of_policy_privacy unavailable'
        logger.error('detect_urls_of_policy_privacy failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('The URLs detection process were successful')
        return pp_List, flg
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
                logger.debug('There are domains in common')
                app_list.append(url)
                flg = True
            else:
                logger.debug('There are no domains in common')
                third_list.append(url)
                flg = False
    except Exception as e:
        reason = 'inform_url_belong unavailable'
        logger.error('inform_url_belong failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('Match tokens were successful')
        return app_list, third_list

#This function allow to read each line of a txt document
def apk_list(path):
    try:
        datos = []
        with open(path) as fname:
            lineas = fname.readlines()
            for linea in lineas:
                datos.append(linea.strip('\n'))

    except Exception as e:
        reason = 'apk_list unavailable'
        logger.error('apk_list failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('The function was successful')
        return datos
#This function stored the result of microservice 2
def writeJson(version, name, flag):
    lstApp = []
    try:
        logger.debug('The function was initiate')
        lstApp.append({
            'name': name,
            'version': version,
            'empty url': flag
        })
        with open('result/results.json', '+a') as fp:
            fp.write(
                ',\n'.join(json.dumps(j) for j in lstApp) +
                '\n')
    except Exception as e:
        reason = 'writeJson unavailable'
        logger.error('writeJson failed',
                     extra={'exception_message': str(e), 'reason': reason})

def writeURLjson(lstURL):
    lstWrite = []
    try:
        for i in range(0, len(lstURL), 1):
            lstWrite.append({
                'n': i,
                'url': lstURL[i]
            })
        with open('result/results.json', '+a') as fp:
            fp.write(
                ',\n'.join(json.dumps(i) for i in lstWrite) +
                '\n')
    except Exception as e:
        reason = 'writeURLjson unavailable'
        logger.error('writeURLjson failed',
                     extra={'exception_message': str(e), 'reason': reason})
# #--------------------------------------------------------------
#                       MAIN CODE
#----------------------------------------------------------------
def Service2():

    print('Enter to the Microserice 2')
    path = input()
    elements  = apk_list(path)
    for app in elements:
        logger.info('Executing the microservice 2')
        try:
            [urlsList, appName, appVersion, appPackage] = get_urls_apk(app)
            print()
            print('The app name is : '+appName)
            [PPurlsList, flagEmpty] = detect_urls_of_policy_privacy(urlsList)
            if flagEmpty == True:
                logger.info('We do not find URLs of Privacy Policy')
                writeJson(appVersion, appName, flagEmpty)
            else:
                [appList, thirdList] = inform_url_belong(PPurlsList, appPackage)
                if len(appList)> 0:
                    logger.info('The following urls belong to the app')
                    writeJson(appVersion, appName, flagEmpty)
                    writeURLjson(appList)
                    for url in appList:
                        print(url)
                if len(thirdList) > 0:
                    logger.info('URLs that belong to third parties are :')
                    writeJson(appVersion, appName, flagEmpty)
                    writeURLjson(thirdList)
                    for url in thirdList:
                        print(url)
            logger.info("The microservice was sucessfull")

        except Exception as e:
            reason = 'get_bag_of_targeted_domains unavailable'
            logger.error('bag of domains failed',
                         extra={'exception_message': str(e), 'reason': reason})

    logger.info('Exit to the microservice')
    os.system("cat result/results.json")

Service2()

logger = stop_logger()
