#------------------------------------------------------------------
#	                    LIBRARIES IMPORT
#------------------------------------------------------------------
from androguard.misc import AnalyzeAPK
import re
import os
from tld import get_tld
import ast
import json
import subprocess
import fnmatch
result_dir = 'result/'
#------------------------------------------------------------------
#                     LOG CONFIGURATION
#------------------------------------------------------------------
import logging as log
from pythonjsonlogger import jsonlogger
handler = None
logger = None
# log agent initialization
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
# log agent termination
def stop_logger():
    logger.removeHandler(handler)
    handler.close()
# log agent definition
logger = init_logger('logs.privapp.log')
#------------------------------------------------------------------
#                     FUNCTIONS CONFIGURATION
#------------------------------------------------------------------
# Obtain the reverse domain of the app_packaege
def reverse_domain(domain):
    try:
        logger.debug('reverse_domain function has been started')
        return '.'.join(reversed(domain.split('.')))
    except Exception as e:
        reason = 'get_bag_of_targeted_domains unavailable'
        logger.error('bag of domains failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('reverse_domain function has been successful')
# Function to obtain the tokens of the package
def get_bag_of_package_domains(apk_package):
    try:
        logger.debug('get_bag_of_package_domains function has been started')
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
        logger.debug('get_bag_of_package_domains function has been successful')
        return [d for d in bag_of_package_domains if
                d not in ['com', 'org', 'net', 'int', 'edu', 'gob', 'www', 'sites']]
# Function to obtain the tokens of the url
def get_bag_of_url_domains(domain):
    try:
        logger.debug('get_bag_of_url_domains function has been started')
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
        logger.debug('get_bag_of_url_domains function has been successful')
        return [d for d in bag_of_targeted_domains if d not in ['www']]
# Function to obtain the urls of the APK
def get_urls_apk(path):
    url_List = []
    try:
        logger.debug('Using AndroGuard')
        a, d, dx = AnalyzeAPK(path)
        app_name = a.get_app_name()
        app_version = a.get_androidversion_name()
        app_package = a.get_package()
        logger.debug('Filtering urls from the obtained strings ')
        regex_result = dx.find_strings('http*')
        for element in regex_result:
            url = element.get_value()
            url_List.append(str(url))
    except Exception as e:
        reason = 'get_urls_apk unavailable'
        logger.error('get_urls_apk failed',
                     extra={'exception_message': str(e),'reason': reason})
    else:
        logger.debug('Extraction of urls and metadata has been successful')
        return url_List, app_name, app_version, app_package
# Function to detect urls with key-words
def detect_urls_of_policy_privacy(url_List):
    privacypolicy_List = []
    try:
        logger.debug('detect_urls_of_policy_privacy function has been started')
        pattern = ['policy', 'privacy', 'politica', 'privacidad']
        for regex in pattern:
            privacypolicy_urls = [aux for aux in url_List if re.search(regex, aux)]
            privacypolicy_List.extend(privacypolicy_urls)
        if len(privacypolicy_List) != 0:
            logger.info('Privacy policy url has been found')
            url_Flag = False
        else:
            logger.info('Privacy policy url has not been found')
            url_Flag = True
    except Exception as e:
        reason = 'detect_urls_of_policy_privacy unavailable'
        logger.error('detect_urls_of_policy_privacy failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('detect_urls_of_policy_privacy function has been successful')
        return privacypolicy_List, url_Flag
# Function to inform if the url PP belongs to the app or to a third party
def inform_url_belong(url_List, package):
    app_List = []
    third_List = []
    try:
        logger.debug('inform_url_belong function has been started')
        package_tokens = get_bag_of_package_domains(package)
        for url in url_List:
            url_tokens = get_bag_of_url_domains(url)
            common_elements = set(package_tokens) & set(url_tokens)
            if len(common_elements) > 0:
                logger.debug('There are domains in common')
                app_List.append(url)
                belong_Flag = True
            else:
                logger.debug('There are no domains in common')
                third_List.append(url)
                belong_Flag = False
    except Exception as e:
        reason = 'inform_url_belong unavailable'
        logger.error('inform_url_belong failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('inform_url_belong function has been successful')
        return app_List, third_List
# Function to allow to read each line of a txt document
def apk_list(path):
    data = []
    try:
        with open(path) as fname:
            lines = fname.readlines()
            for line in lines:
                data.append(line.strip('\n'))
    except Exception as e:
        reason = 'apk_list unavailable'
        logger.error('apk_list failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        return data
# Function to store the result of microservice 2
def writeJson(version, name, url_flag, url_belong):
    lstApp = []
    try:
        logger.debug('The function was initiate')
        lstApp.append({'name': name,'version': version,
                       'belong url': url_belong,'empty url': url_flag})
        with open(result_dir+'results.json', '+a') as fp:
            fp.write(',\n'.join(json.dumps(line) for line in lstApp)+'\n')
    except Exception as e:
        reason = 'writeJson unavailable'
        logger.error('writeJson failed',
                     extra={'exception_message': str(e), 'reason': reason})
# Function to write URLS in the results
def writeURLjson(lstURL):
    lstWrite = []
    try:
        for aux in range(0, len(lstURL), 1):
            lstWrite.append({'n': aux,'url': lstURL[aux]})
        with open(result_dir+'results.json', '+a') as fp:
            fp.write(',\n'.join(json.dumps(aux2) for aux2 in lstWrite)+'\n')
    except Exception as e:
        reason = 'writeURLjson unavailable'
        logger.error('writeURLjson failed',
                     extra={'exception_message': str(e), 'reason': reason})
# #--------------------------------------------------------------
#                       MAIN CODE
#----------------------------------------------------------------
def Service2():
    print('Entering microservice 2')
    path = input()
    print('Executing the microservice 2')
    elements = apk_list(path)
    for app in elements:
        logger.info('Executing the microservice 2')
        try:
            [urlsList, appName, appVersion, appPackage] = get_urls_apk(app)
            print('--------------------------------------------------------')
            print('Extracting character strings from APK')
            print('The app name is : '+appName)
            print('Searching for privacy policy url')
            [PPurlsList, flagEmpty] = detect_urls_of_policy_privacy(urlsList)
            if flagEmpty:
                print('**** Privacy policy URL not found ****')
                logger.info('Privacy policy URL not found')
                writeJson(appVersion, appPackage, flagEmpty, None)
            else:
                print('**** Privacy policy URL found ****')
                logger.info('Privacy policy URL found')
                [appList, thirdList] = inform_url_belong(PPurlsList, appPackage)
                if len(appList)>0:
                    logger.info('The following urls belong to the app')
                    writeJson(appVersion, appPackage, flagEmpty, True)
                    writeURLjson(appList)
                    for url in appList:
                        print(url)
                elif len(thirdList)>0:
                    logger.info('URLs belong to third parties')
                    writeJson(appVersion, appPackage, flagEmpty, False)
                    writeURLjson(thirdList)
                    for url in thirdList:
                        print(url)
            logger.info("The microservice 2 was successful")

        except Exception as e:
            print('Error while microservice 2, review logs.privapp.log')
            reason = 'Error during executing service2'
            logger.error('Service2',
                         extra={'exception_message': str(e), 'reason': reason})
    print('--------------------------------------------------------')
    print('Leaving microservice 2')
    print()
    logger.info('Leaving microservice 2')
    os.system("cat "+result_dir+"results.json")
#
# Running microservice2
#
Service2()
logger = stop_logger()
