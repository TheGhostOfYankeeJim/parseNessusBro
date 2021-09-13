import xml.etree.ElementTree as ET

# This just parses nessus file for www services and creates a list to use for burp, and my other loadTheURLBro.py
def parseForWeb(file_name):
	# create a list to house all our target URLs
	currentHostsWithWebServer = []
	
	# get the tree
	tree = ET.parse(file_name)
	#print(tree.getroot())
	root = tree.getroot()
	#print("tag=%s, attrib=%s" % (root.tag, root.attrib))
	
	# I think I can just find all and parse from there? 

	for tag in root.findall('Report/ReportHost'):
		#print(tag)
		#print(tag.get('name')) # now prints the IP
		currentHostName = (tag.get('name'))
		for currentHost in tag.findall('ReportItem'):
			serviceWWW = currentHost.get("svc_name")
			if serviceWWW == "www":
				
				# I know I can use OR statements but I'm just being painfully clear below
				portService = currentHost.get("port")
				if portService == "80":
					#print("http://" + currentHostName + ":" + portService)
					currentHostsWithWebServer.append("http://" + currentHostName)
				
				elif portService == "8080":
					#print("http://" + currentHostName + ":" + portService)
					currentHostsWithWebServer.append("http://" + currentHostName + ":" + portService)
				
				elif portService == "8008":
					#print("http://" + currentHostName + ":" + portService)
					currentHostsWithWebServer.append("http://" + currentHostName + ":" + portService)
				
				elif portService == "443":
					#print("https://" + currentHostName + ":" + portService)
					currentHostsWithWebServer.append("https://" + currentHostName)
				
				elif portService == "8443":
					#print("https://" + currentHostName + ":" + portService)
					currentHostsWithWebServer.append("https://" + currentHostName + ":" + portService)
				
				elif portService == "9443":
					#print("https://" + currentHostName + ":" + portService)
					currentHostsWithWebServer.append("https://" + currentHostName + ":" + portService)
				
				# Anything else is probably https, burp and many other programs will test either protocal as well
				else:
					#print(currentHostName + ":" + portService)
					currentHostsWithWebServer.append("https://" + currentHostName + ":" + portService)
	
	# Now we get rid of dups in our lists
	currentHostsWithWebServer = list(dict.fromkeys(currentHostsWithWebServer))
	#print(currentHostsWithWebServer)
	for webHostFound in currentHostsWithWebServer:
		print(webHostFound)		

# Won't Generate output while this fuction is still being developed 		
# TLS Testing Section
#def parseForWeb(file_name):
	# create a list to house all our target hosts with TLS/SSL 
#	currentHostsWithTLS_SSL = []

if __name__ == "__main__":
   parseForWeb("reportTarget.nessus")
