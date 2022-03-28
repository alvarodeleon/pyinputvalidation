#/usr/bin/python3.9
# -*- coding: utf-8 -*-

import sys
import re
import hashlib
import base64
import chardet
from chardet.universaldetector import UniversalDetector


def filters(value,rules):
	v = Validators()
	return v.filters(value, rules)

def checks(value,rules):
	v = Validators()
	return v.rules(value,rules)

def apply(value,rules):

	lst_rules = ['!empty','!none','domain','ip','mail','integer','float','number','filename']
	lst_filters = ['trim','md5','html','base64encode','base64decode','upper','uppercase','lower','lowercase','utf8','utf-8']

	explode_rules = filters.split(',')

	if value is not None:
		for _rule in explode_rules:

			if _rules in lst_rules:
				v = Validation()
				r  = v.rules(value,_rule)
				if r == False:
					return False

			if _rules in lst_filters:
				v = Validation()
				value = v.filters(value,_rule)

	return 0

class Validation:

	def filters(value,rules):
		val = Validators()
		return val.filters(value,rules)

	def rules(value,rules):
		val = Validators()
		return val.rules(value,rules)

	def form(data):
		return  FormValidation(data) 

	def validators():
		return Validators()


class Validators:
	'''
	def __init__(self):
		return self
	'''

	def filters(self,value,filters):

		#escape or sanitize

		#Convert to string,integer,


		explode_filters = filters.split(',')

		if value is not None:

			for _filter in explode_filters:

				if _filter == 'trim':
					value = self.trim(value)

				if _filter == 'md5':
					version = sys.version

					if version[:1] == '2':
						value = hashlib.md5(value).hexdigest()
					else:
						value = hashlib.md5(value.encode('utf-8')).hexdigest()

				if _filter == 'sha1' or _filter == 'sha-1':
					h = hashlib.new('sha1')
					h.update(str.encode(value))
					value = h.hexdigest()

				if _filter == 'sha2' or _filter == 'sha-2':
					h = hashlib.new('sha224')
					h.update(str.encode(value))
					value = h.hexdigest()

				if _filter == 'sha224' or _filter == 'sha-224':
					h = hashlib.new('sha224')
					h.update(str.encode(value))
					value = h.hexdigest()

				if _filter == 'sha256' or _filter == 'sha-256':
					h = hashlib.new('sha256')
					h.update(str.encode(value))
					value = h.hexdigest()

				if _filter == 'sha384' or _filter == 'sha-384':
					h = hashlib.new('sha384')
					h.update(str.encode(value))
					value = h.hexdigest()

				if _filter == 'sha512' or _filter == 'sha-512':
					h = hashlib.new('sha512')
					h.update(str.encode(value))
					value = h.hexdigest()

				if _filter == 'html':
					pass

				if _filter == 'base64encode' or _filter == 'b64e':
					value_bytes = value.encode('ascii')
					base64_bytes = base64.b64encode(value_bytes)
					value = base64_bytes.decode("ascii")

				if _filter == 'base64decode' or _filter == 'b64d':
					base64_bytes = value.encode('ascii')
					value_bytes = base64.b64decode(base64_bytes)
					value = value_bytes.decode('ascii')

				if _filter == 'upper' or _filter == 'uppercase':
					value = value.upper()

				if _filter == 'lower' or _filter == 'lowercase':
					value = value.lower()

				if _filter == 'html':
					value =  self.html(value)

				if _filter == 'utf8' or _filter == 'utf-8':

					value = bytes(value,'utf8').decode('utf-8')

				if _filter == 'integer' or _filter == 'int':
					try:
						value = int(value)
					except:
						value = 0
		return value

	def rules(self,value,rules):

		check = True

		explode_rules = rules.split(',')

		if value is not None:

			for rule in explode_rules:

				if rule == '!empty':
					if self.empty(value):
						check = False

				if rule == '!none':
					if value is None:
						check = False

				if rule == 'domain':
					if not self.domain(value):
						check = False

				if rule == 'ip':
					if not self.ip(value):
						check = False

				if rule == 'mail':
					if not self.mail(value):
						check = False

				if rule == 'integer' or rule == 'int':
					if not self.integer(value):
						check = False

				if rule == 'float':
					if not self.float(value):
						check = False

				if rule == 'numeric':
					if not self.numeric(value):
						check = False

				if rule == 'filename':
					if not self.numeric(value):
						check = False
				if rule == 'string' or rule == 'str':
					if not self.string(value):
						check = False

			return check
		else:
			return False



	#Arrays
	def options(self,value,options):

		if self.empty(value):
			return False

		if value in options:
			return True
		else:
			return False

	#Contents

	def domain(self,value):

		if self.empty(value):
			return False

		if value.find('.') < 1:
			return False

		return bool(re.match("^(?=.{1,255}$)(?!-)[A-Za-z0-9\-]{1,63}(\.[A-Za-z0-9\-]{1,63})*\.?(?<!-)$",value))

	def ip(self,value):

		if self.empty(value):
			return False

		tmp = bool(re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$",value))

		if tmp==True:
			explode = value.split(".")

			if len(explode)>0:
				for i in explode:
					if not self.integer(i):
						return False

					if int(i) > 255:
						return False

		return tmp


	def mail(self,value):

		if self.empty(value):
			return False

		#if re.match('^[a-z0-9\.]+[@]\w+[.]\w{2,3}+[.]\w{2,3}$',value) or re.match('^[a-z0-9\.]+[@]\w+[.]\w{2,3}$',value):
		#if re.match("^[a-z0-9\.]+[@][a-z0-9\.].+[.]\w{2,3}$",value):
		return bool(re.match("^[a-z0-9\.]+[@][a-z0-9\.].+[.]\w.*$",value))

	def filename(self,value):

		if self.empty(value):
			return False

		return re.match("^[A-Za-z0-9\_\-\.]+$",value)

	#States

	def empty(self,value):

		if value is None:
			return True

		try:
			if self.numeric(value):
				if value < 1:
					return True
				else:
					return False
			elif self.string(value):
				if len(value)<1:
					return True
				else:
					return False
		except:
			return False

	#types
	def string(self,value):

		if isinstance(value,str):
			return True
		else:
			try:
				val = str(value)
				return True
			except:
				return False

	def integer(self,value):

		if self.empty(value) and value!=0:
			return False

		if isinstance(value,int):
			return True
		else:
			try:
				value = int(value)
				return True

			except:
				return False

	def float(self,value):

		if value=="":
			return False

		if isinstance(value,str):
			if value.find(",")>0:
				value = value.replace(',','.')

		if isinstance(value,float):
			return True
		else:
			try:
				val = float(value)
				return True
			except:
				return False

	def numeric(self,value):
		if self.integer(value) or self.float(value):
			return True
		else:
			return False

	#Filters
	def trim(self,value):
		return value.strip()

	def html(self,value):
		charset = {
			'"':'&quot;','&':'&amp;','<':'&lt;','>':'&gt;','¡':'&iexcl;','¢':'&cent;','£':'&pound;','¤':'&curren;','¥':'&yen;',
			'¦':'&brvbar;','§':'&sect;','¨':'&uml;','©':' &copy;','ª':'&ordf;','«':'&laquo;','¬':'&not;','®':'&reg;','¯':' &macr;','°':'&deg;','±':'&plusmn;',
			'²':'&sup2;','³':'&sup3;','´':'&acute;','µ':'&micro;','¶':'&para;','·':'&middot;','¸':'&cedil;','¹':'&sup1;','º':'&ordm;','»':'&raquo;','¼':'&frac14;','½':'&frac12;',
			'¾':'&frac34;','¿':'&iquest;','À':'&Agrave;','Á':'&Aacute;','Â':'&Acirc;','Ã':'&Atilde;','Ä':'&Auml;','Å':'&Aring;','Æ':'&AElig;','Ç':'&Ccedil;','È':'&Egrave;',
			'É':'&Eacute;','Ê':'&Ecirc;','Ë':'&Euml;','Ì':'&Igrave;','Í':'&Iacute;','Î':'&Icirc;','Ï':'&Iuml;','Ð':'&ETH;','Ñ':'&Ntilde;','Ò':'&Ograve;','Ó':'&Oacute;',
			'Ô':'&Ocirc;','Õ':'&Otilde;','Ö':'&Ouml;','×':'&times;','Ø':'&Oslash;','Ù':'&Ugrave;','Ú':'&Uacute;','Û':'&Ucirc;','Ü':'&Uuml;','Ý':'&Yacute;','Þ':'&THORN;',
			'ß':'&szlig;','à':'&agrave;','á':'&aacute;','â':'&acirc;','ã':'&atilde;','ä':'&auml;','å':'&aring;','æ':'&aelig;','ç':'&ccedil;','è':'&egrave;','é':'&eacute;',
			'ê':'&ecirc;','ë':'&euml;','ì':'&igrave;','í':'&iacute;','î':'&icirc;','ï':'&iuml;','ð':'&eth;','ñ':'&ntilde;','ò':'&ograve;','ó':'&oacute;','ô':'&ocirc;','õ':'&otilde;',
			'ö':'&ouml;','÷':'&divide;','ø':'&oslash;','ù':'&ugrave;','ú':'&uacute;','û':'&ucirc;','ü':'&uuml;','ý':'&yacute;','þ':'&thorn;','ÿ':'&yuml;','€':'&euro;'
		}

		length = len(value);

		new_str = ''

		for i in range(0,length):
			if value[i] in charset:
				new_str += str(charset[value[i]])
			else:
				new_str += str(value[i])

		return new_str

	def utf8(self,value):
		return value.decode('utf-8')
	
	'''
	def ascii(self,value):
		return value.decode('ascii')
	'''

class FormValidation:

	__data = None
	__errors = []
	__fields_cheched = []

	__fields_map = {}

	def __init__(self,data):
		self.__data = data

	def rules(self,field,rules,options=None):

		#Validation with validators
		validator = Validators()

		if field.find(":") != -1:
			names =  field.split(':')
			self.__fields_map[names[0]] = names[1]
			field = names[0]
		else:
			self.__fields_map[field] = field

		if field in self.__data:

			if not validator.rules(self.__data[field],rules):
				self.__errors.append('{} is not valid'.format(field))


			self.__fields_cheched.append(field)

		#Required
		explode_rules = rules.split(',')

		for rule in explode_rules:

			if rule=='required':
				if field not in self.__data:
					self.__errors.append('{} is required'.format(field))

			if rule=='options':
				if field in self.__data:
					if not validator.options(self.__data[field],options):
						self.__errors.append('{} is not valid'.format(field))

	def filters(self,field,filters):
		validator = Validators()
		self.__data[field] = validator.filters(self.__data[field],filters)


	def getErrors(self):
		return self.__errors

	def getData(self):
		return self.__data

	def check(self):

		tmp = {}

		for field in self.__data:
			if field in self.__fields_cheched:
				tmp[self.__fields_map[field]] = self.__data[field]

		self.__data = tmp

		if len(self.__errors)>0:
			return False
		else:
			return True

