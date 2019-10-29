from __future__ import print_function
import os
from argparse import RawTextHelpFormatter
import argparse
import hashlib
import requests
import time
import re
import pefile
import sys
import mmap
import shutil
from backports import lzma

# make sure you install the following:
# pip2 install -i https://pypi.anaconda.org/carlkl/simple backports.lzma
# pip2 install pefile 
# pip2 install requests

# Projects used and thanks:
# 	https://github.com/sptonkin/nsrlsearch
# 	https://gist.github.com/petri/4a442d4f3ff4e4427bc9933daecf6aba
# 	https://github.com/secretsquirrel/SigThief
# 	https://pypi.org/project/pefile/#files
# 	https://github.com/h3collective/pe_cert_mutator/blob/master/cert_mutator.py
# 	to read big files: https://stackoverflow.com/questions/4940032/how-to-search-for-a-string-in-text-files

url = 'https://www.virustotal.com/vtapi/v2/file/'
apikey = '<------------- API KEY GOES HERE ----------------->'
allfiles = []
forlaterMd5 = []
forlaterFname = []
logfile =  'vt-automate-log.txt'
rdshashes = 'latesthashes.txt'

parser = argparse.ArgumentParser(
	description='''
This program takes a Windows folder as input and filters by extension (e.g. exe).
It will automatically check their MD5 hashes at Virustotal, but it will filter out digitally signed ones and known good files based on the NIST database here: http://www.nsrl.nist.gov
If the file is not yet submitted, it will automatically upload it to Virustotal and wait to get the results.
It takes two arguments, the folder (-f) and the extension (-e).
A file called "vt-automate-log.txt" will be created at the current working directory, containing the Virustotal results for the files that have been detected as malicious.\n''', 
	formatter_class=RawTextHelpFormatter)

parser.add_argument('-f', '--folder', help='folder, e.g. C:\\Windows\\System32', required=True)
parser.add_argument('-e', '--extension', help='extension, e.g. exe', required=True)
args = vars(parser.parse_args())
folderName = args['folder']
extension = args['extension']

def createFilesList(extension):
	for root, dirs, files in os.walk(folderName):
	    for file in files:
	        if file.endswith('.' + extension):
				allfiles.append((os.path.join(root, file)))

def calculateMD5(fname):
	m = hashlib.md5()
	try:
		with open(fname, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
				m.update(chunk)
		f.close()
		print('[+] File ' + fname + ' has md5 hash: ' + m.hexdigest())
		return m.hexdigest()
	except:
		sys.exit('[ERROR] Can\'t open file ' + fname + ' for read.')		

def submitHash(h):
	resource = h
	params = {'apikey': apikey, 'resource': resource}
	try:
		response = requests.get(url + 'report', params=params)
	except:
		sys.exit('[ERROR] Do you have a direct, working Internet connection?')
	try:
		return response.json()
	except ValueError:
		print(response)
		sys.exit('[ERROR] Unprivileged API keys need 1 min pause for every 4 submissions')


def getPESignature(fname):
	try:
		print('[+] Getting PE signature of file ' + fname)		
		f = open(fname, 'rb')
		data = f.read()
		f.close()
	except:
		print('[ERROR] can\'t read file contents.')
		return False
	
	try:
		pecontents = pefile.PE(data=data)
		security_data_dir = pecontents.OPTIONAL_HEADER.DATA_DIRECTORY[4]
		security_offset = security_data_dir.VirtualAddress
		security_size = security_data_dir.Size
	except:
		print('[ERROR] ' + fname + ' is not a valid PE file.')
		return False

	if security_data_dir.VirtualAddress == 0:
		print('[+] File ' + fname + ' has no signature')
		return True
	print ('[+] File ' + fname + ' is signed. Getting next.')
	#print data[security_offset:security_offset+security_size]
	
	return False

def downloadLatestRDS():
	cwd = os.getcwd()
	rdsurl = 'https://nsrllookup.com/hashes/Sep2019.txz'
	try:
		print('[+] Downloading latest RDS list from https://nsrllookup.com/hashes/Sep2019.txz. Its size is around 2.5GB\n')
		r = requests.get(rdsurl)
	except:
		sys.exit('[ERROR] Do you have a direct, working Internet connection?')
	
	try:
		with open(cwd + '/latesthashes.txz', 'wb') as f:
			f.write(r.content)
	except:
		sys.exit('[ERROR] can\'t write data to disk.')
	f.close()

	# unzip and set name to latesthashes.txt (thanks to http://tiny.cc/ssxdfz):
	i = 'latesthashes.txz'
	with lzma.open(i) as compressed:
		o = rdshashes
		with open(o, 'wb') as destination:
			shutil.copyfileobj(compressed, destination)

	return True

def checkNISTdb(h, rdslist):
	try:
		with open(rdslist) as f:
			s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
			print('[+] Searching for md5 hash ' + h + ' at the latest RDS list, referenced by the file: ' + rdslist)
			if re.search(br'(?i)' + h, s):
				print('[+] hash ' + h + ' found in the RDS database, proceeding to next file')
				return False
		f.close()
	except:
		sys.exit('[ERROR] The RDS list does not exist.')
	print('[+] hash ' + h + ' not found in the RDS database.')
	return True

def submitFile(fname):
	try:
		filesize = os.path.getsize(fname)
	except:
		print('[ERROR] Cannot get filesize of file: ' + fname)
		return False
	
	if filesize >= 33554432:
		print('[-] ' + fname + ' size is larger than 32MB. Need privileged API for this. Skipping.')
		return False
	
	print('[+] ' + fname + ' is being uploaded...')
	params = {'apikey': apikey}
	upfiles = {'file': (fname, open(fname, 'rb'))}
	
	try:
		response = requests.post(url + 'scan', files = upfiles, params = params)
	except:
		sys.exit('[ERROR] Do you have a direct, working Internet connection?')

	try:		
		kati = response.json()
		md5forlater = kati[u'md5']
		if re.match(r"([a-fA-F\d]{32})", md5forlater):
			forlaterMd5.append(md5forlater)
			forlaterFname.append(fname)
			print('[+] File ' + fname + ' submitted for scanning. Check its md5 later.')
	except:
		print('[ERROR] File ' + fname + ' submitted but cannot read response.')

def writePathToFile(fname, h, avnumber):
	cwd = os.getcwd()
	logContent = 'File: ' + fname + '. MD5hash: ' + h + '. ' , avnumber, ' antivirus engines detected it as malicious.\n'
	logContentAsString = ''.join(map(str, logContent))
	try:
		f = open(cwd + '\\' + logfile, 'a')
		f.write(str(logContentAsString))
	except:
		sys.exit('[ERROR] can\'t write data to disk.')

	f.close()

	return True

def main():
	print ('[+] Creating list of files, please be patient.')
	createFilesList(extension)
	if not len(allfiles):
		sys.exit('[+] No files found.')
	print('[+] Created files list with', len(allfiles), 'files to check.\n')
	timeInMins = (len(allfiles) * 15 / 60) + 2 
	print('[+] It will take approximately', timeInMins, 'minutes to finish.' )

	downloadLatestRDS()

	for file in allfiles:
		if getPESignature(file) == True:
			md5hash	= calculateMD5(file)
			if checkNISTdb(md5hash, rdshashes) == True:
				print ('[+] Submitting file ' + file + ' with md5 hash ' + md5hash + ' to VT.')
				time.sleep(15)
				r = submitHash(md5hash)
				if r[u'response_code'] == -2:
					sys.exit('[ERROR] Resource is queued for analysis. Exiting...')

				if r[u'response_code'] == 0:
					print('[+] ' + file + ' is not known and needs to be submitted.')
					submitFile(file)

				else:
					if r[u'positives'] == 0:
						print('[+] ' + file + ' seems safe.')
					else: 
						print('[+] ' + file + ' is marked as malicious by', r[u'positives'], 'antivirus engines.')
						writePathToFile(file, md5hash, r[u'positives'])
			
		print('\n')

	if forlaterMd5 and forlaterFname:
		print('[+] Now checking the submitted files... Will sleep 2 minutes to get the reports...')
		time.sleep(120)
		for md5hash in forlaterMd5:
			for fname in forlaterFname:
				r = submitHash(md5hash)
				time.sleep(15)
				if r[u'response_code'] == -2:
					sys.exit('[ERROR] Resource is queued for analysis. Exiting...')
				if r[u'positives'] == 0:
					print('[+] ' + md5hash + ' seems safe.')
				else:
					print('[+] File ' + fname + ' with md5 hash ' + md5hash + ' is marked as malicious by', r[u'positives'], 'antivirus engines.')
					writePathToFile(fname, md5hash, r[u'positives'])

if __name__ == '__main__':
    main()