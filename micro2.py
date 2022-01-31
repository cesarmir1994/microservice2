from androguard.misc import AnalyzeAPK
import re
import os
import sys
import logging
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

def InputArgs():
    logger.debug("Comprobate the input arguments")
    try:
        assert len(sys.argv)==2, 'ERROR: You do not ingress 2 arguments'
    except Exception as error:
        logger.error(error)
        exit(0)

InputArgs()

path = sys.argv[1]

logger.debug('Usando Androguard')

a, d, dx = AnalyzeAPK(path)

logger.debug('Se cargo todos los modulos')

name = a.get_app_name()

print(name)

logger.debug('Filtrando los urls de los strings obtenidos')

d1 = dx.find_strings('http*')

file = open(name+'urls.txt', 'w')

for i in d1:
	url = i.get_value()
	#print(url)
	file.write(str(url)+'\n')

file.close()

PP = []
datos = []
with open(name+'urls.txt') as fname:
	lineas = fname.readlines()
	for linea in lineas:
		datos.append(linea.strip('\n'))

print('Se han obtenido un total de '+str(len(datos))+' urls')

pattern = ['policy', 'privacy', 'politica', 'privacidad']

for regex in pattern:
	reg = 'r'+regex
	patt=re.compile(reg)
	str_match = [x for x in datos if re.search(regex, x)]
	PP.extend(str_match)

if len(PP) != 0:
	
	print('Si se encontro parentesco con las urls de privacidad')
	logger.info('Si se encontro parentesco con las urls de privacidad')
	file = open(name+'urlsPP.txt', 'w')

	for line in PP:
		file.write(line+'\n')

	file.close()
else:
	logger.info('No se encontro parentesco con las urls de privacidad')


logger = stop_logger()
