#############
# LIBRARIES #
#############

import urllib2
import urllib
import argparse
import os
import xml.etree.cElementTree as ET
import time # For converting epoch to normal time

##################
# LOGIN FUNCTION #
##################

def login():
	# API Call to login to Nessus
	log = urllib2.urlopen('https://localhost:8834/login/','login=brian&password=password')
	
	# Parsing XML for the token, needed for all future API calls requiring authentication
	tree = ET.parse(log)
	tree.getroot()
	for elem in tree.findall('contents/token'):
		token = elem.text
		return token

####################
# REPORTS FUNCTION #
####################

def reports():
	# Retrieving a token from the login() function
	token = login()

	# API Call to get a list of reports on Nessus Server
	report = urllib2.urlopen('https://localhost:8834/report/list', 'token=' + token)

	# Header for listed reports
	print ""
	print "Nessus CLI v1.0"
	print "---------------------------------------------------------------------------------------------------------------------"
	print "Report Name".ljust(20), "Status".ljust(20), "Date/Time".ljust(22), "UUID"		
	print "---------------------------------------------------------------------------------------------------------------------"

	# Parse XML for all the reports, then grabs the name, status and timestamp of each report.
	tree = ET.parse(report)
	tree.getroot()
	for elem in tree.findall('contents/reports/'): 
		name = elem.find('readableName').text
		status = elem.find('status').text
		timestamp = elem.find('timestamp').text
		uuid = elem.find('name').text
		
		# Convert the epoch string timestamp into a readable timestamp format
		floatedtime = float(timestamp)
		truetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(floatedtime))
			
		# Print the Report information in format with Header
		print name.ljust(20), status.capitalize().ljust(20), truetime.ljust(22), uuid

#####################
# Create a New Scan #
#####################

def newscan():
	
	# Retrieving the token from the login() function
	token = login()
	
	# Asking for scan information
	scanname = args.scanname
	target = args.target
	policy = args.policy
	# Manually URL Encoding . to %2E, since urlencode doens't encode .'s
	x = target.replace('.','%2E')

	# API Call to create a new scan, using the token as authentication, a scan name, the targets, and policy ID
	scan = urllib2.urlopen('https://localhost:8834/scan/new', 'token=' + token + '&scan%5fname=' + 
	scanname + '&target=' + target + '&policy%5fid='+ policy)

	# Printing the Header
	print ""
	print "Nessus CLI v1.0"
	print "-----------------------------------------------------------------------"
	print "Report Name".ljust(20), "Date/Time Created".ljust(20), "UUID"		
	print "-----------------------------------------------------------------------"
	
	# Parse XML for valuable information from new scan.
	tree = ET.parse(scan)
	tree.getroot()
	for child in tree.iter('scan'):
		uuid = child.find('uuid').text
		start_time = child.find('start_time').text
		scan_name = child.find('scan_name').text
		
		# Convert the epoch string timestamp into a reable timestamp format
		floatedstarttime = float(start_time)
		truetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(floatedstarttime))

		# Print the New Scan information in format with the header
		print scan_name.ljust(20), truetime.ljust(20), uuid

#####################
# Policies Function #
#####################

def policies():
	# Retrieving the token from the login() function
	token = login()

	# API Call to get a list of the policies
	scan = urllib2.urlopen('https://localhost:8834/policy/list', 'token=' + token)

	#Printing the Header
	print ""
	print "Nessus CLI v1.0"
	print "-----------------------------------------------------------------------"
	print "Name".ljust(20), "ID".ljust(5), "Owner".ljust(10), "Comments"		
	print "-----------------------------------------------------------------------"

	# Parse XML for Policy ID and information
	tree = ET.parse(scan)
	tree.getroot()
	for child in tree.iter('policy'):
		policyid = child.find('policyID').text
		policyname = child.find('policyName').text
		policyowner = child.find('policyOwner').text
		policycomments = child.find('policyContents/policyComments').text

		#Print the Policy Information in format with the header
		print policyname.ljust(20), policyid.ljust(5), policyowner.ljust(10), policycomments

#################
# Load Function #
#################

def load():
	# Retrieving the token from the login() function
	token = login()

	# API Call to get load values
	scan = urllib2.urlopen('https://localhost:8834/server/load', 'token=' + token)
	
	# Printing the Header
	print ""
	print "Nessus CLI v1.0"
	print "---------------------------------------------------------------------------------"
	print "# Of Scans".ljust(15), "# Of Sessions".ljust(15), "# Of Hosts".ljust(15), "# Of TCP Sessions".ljust(20), "Load Average"		
	print "---------------------------------------------------------------------------------"

	# Parsing XML
	tree = ET.parse(scan)
	tree.getroot()
	for child in tree.iter('load'):
		numscans = child.find('num_scans').text
		numsessions = child.find('num_sessions').text
		numhosts = child.find('num_hosts').text
		numtcp = child.find('num_tcp_sessions').text
		loadavg = child.find('loadavg').text

		print "    " + numscans.ljust(15), numsessions.ljust(15), numhosts.ljust(15), numtcp.ljust(20), loadavg

##############################
# Parsing Arguments Function #
##############################

def parse_args():

	# Option Parsing
	parser = argparse.ArgumentParser(__file__, description="Nessus CLI")
	parser.add_argument('-r', '--reports', help='List all reports', action="store_true")
	parser.add_argument('-n', '--newscan', help='Creates a new scan', action="store_true")
	parser.add_argument('-p', '--policies',help='List all policies', action="store_true")
	parser.add_argument('-l', '--load', help='Get the current load', action="store_true")
	parser.add_argument('--target', help='Specify a target', dest="target")
	parser.add_argument('--policy', help='Specify a policy', dest="policy")
	parser.add_argument('--scanname', help='Specify a name for the scan', dest="scanname")
	args = parser.parse_args()
	return args

#################
# Main Function #
#################

if __name__ == '__main__':
	args = parse_args()
	if (args.reports):
		reports()
	elif (args.newscan):
		newscan()
	elif (args.policies):
		policies()
	elif (args.load):
		load()
