import ldap3
from MakeLog import make_log as log
import sys
import json
import csv
import os

class LoginFailure(Exception):
	"""error"""

class ActiveDireactory(object):
	"""
	
	Active Directory Client Class, authenticate, search, dump

	"""		
		
	def __init__(self, domain='', auth_host='192.168.1.179', username='', password=''):
		"""
		
		Initialise bind
		
		"""
		logger = log.initialise()
		logger.info('test')
		
		try:
			server = ldap3.Server(auth_host, get_info='ALL', allowed_referral_hosts=[('*',True)])
			
			if not username:
				connect = ldap3.Connection(server, authentication='ANONYMOUS')
			else:
				connect = ldap3.Connection(server, user='{}\{}'.format(domain, username), password=password, authentication=ldap3.NTLM, auto_bind=False)
			
			if connect.bind():
				self.ad = connect
				self.logger = logger
				self.domain = domain
				self.username = username
				self.password = password
				self.auth_host = auth_host
			else:
				print('LoginFailure:', connect.result['description'])
				logger.info('LoginFailure: {}'.format(connect.result['description']))
				logger.error('LoginFailure: {}'.format(connect.result))
				sys.exit()
		except Exception:
			logger.error('unhandled exception', exc_info=1)
		
		
	def get_headers(self, data, type_out):
		
		if 'users' in type_out:
		
			header = ["accountExpires", "accountNameHistory", "aCSPolicyName", "adminCount", "adminDescription",
			        "adminDisplayName", "allowedAttributes", "allowedAttributesEffective", "allowedChildClasses",
			        "allowedChildClassesEffective", "altSecurityIdentities", "assistant", "badPasswordTime",
			        "badPwdCount", "bridgeheadServerListBL", "c", "canonicalName", "cn", "co", "codePage", "comment",
			        "company", "controlAccessRights", "countryCode", "createTimeStamp", "dBCSPwd", "defaultClassStore",
			        "department", "description", "desktopProfile", "destinationIndicator", "directReports",
			        "displayName", "displayNamePrintable", "distinguishedName", "division", "dSASignature",
			        "dSCorePropagationData", "dynamicLDAPServer", "employeeID", "extensionName",
			        "facsimileTelephoneNumber", "flags", "fromEntry", "frsComputerReferenceBL", "fRSMemberReferenceBL",
			        "fSMORoleOwner", "garbageCollPeriod", "generationQualifier", "givenName", "groupMembershipSAM",
			        "groupPriority", "groupsToIgnore", "homeDirectory", "homeDrive", "homePhone", "homePostalAddress",
			        "info", "initials", "instanceType", "internationalISDNNumber", "ipPhone", "isCriticalSystemObject",
			        "isDeleted", "isPrivilegeHolder", "l", "lastKnownParent", "lastLogoff", "lastLogon",
			        "legacyExchangeDN", "lmPwdHistory", "localeID", "lockoutTime", "logonCount", "logonHours",
			        "logonWorkstation", "mail", "managedObjects", "manager", "masteredBy", "maxStorage", "memberOf",
			        "mhsORAddress", "middleName", "mobile", "modifyTimeStamp", "mS-DS-ConsistencyChildCount",
			        "mS-DS-ConsistencyGuid", "mS-DS-CreatorSID", "mSMQDigests", "mSMQDigestsMig",
			        "mSMQSignCertificates", "mSMQSignCertificatesMig", "msNPAllowDialin", "msNPCallingStationID",
			        "msNPSavedCallingStationID", "msRADIUSCallbackNumber", "msRADIUSFramedIPAddress",
			        "msRADIUSFramedRoute", "msRADIUSServiceType", "msRASSavedCallbackNumber",
			        "msRASSavedFramedIPAddress", "msRASSavedFramedRoute", "name", "netbootSCPBL", "networkAddress",
			        "nonSecurityMemberBL", "ntPwdHistory", "nTSecurityDescriptor", "o", "objectCategory", "objectClass",
			        "objectGUID", "objectSid", "objectVersion", "operatorCount", "otherFacsimileTelephoneNumber",
			        "otherHomePhone", "otherIpPhone", "otherLoginWorkstations", "otherMailbox", "otherMobile",
			        "otherPager", "otherTelephone", "otherWellKnownObjects", "ou", "pager",
			        "partialAttributeDeletionList", "partialAttributeSet", "personalTitle",
			        "physicalDeliveryOfficeName", "possibleInferiors", "postalAddress", "postalCode", "postOfficeBox",
			        "preferredDeliveryMethod", "preferredOU", "primaryGroupID", "primaryInternationalISDNNumber",
			        "primaryTelexNumber", "profilePath", "proxiedObjectName", "proxyAddresses", "pwdLastSet",
			        "queryPolicyBL", "registeredAddress", "replPropertyMetaData", "replUpToDateVector", "repsFrom",
			        "repsTo", "revision", "rid", "sAMAccountName", "sAMAccountType", "scriptPath", "sDRightsEffective",
			        "securityIdentifier", "seeAlso", "serverReferenceBL", "servicePrincipalName", "showInAddressBook",
			        "showInAdvancedViewOnly", "sIDHistory", "siteObjectBL", "sn", "st", "street", "streetAddress",
			        "subRefs", "subSchemaSubEntry", "supplementalCredentials", "systemFlags", "telephoneNumber",
			        "teletexTerminalIdentifier", "telexNumber", "terminalServer", "textEncodedORAddress",
			        "thumbnailLogo", "thumbnailPhoto", "title", "tokenGroups", "tokenGroupsGlobalAndUniversal",
			        "tokenGroupsNoGCAcceptable", "unicodePwd", "url", "userAccountControl", "userCert",
			        "userCertificate", "userParameters", "userPassword", "userPrincipalName", "userSharedFolder",
			        "userSharedFolderOther", "userSMIMECertificate", "userWorkstations", "uSNChanged", "uSNCreated",
			        "uSNDSALastObjRemoved", "USNIntersite", "uSNLastObjRem", "uSNSource", "wbemPath",
			        "wellKnownObjects", "whenChanged", "whenCreated", "wWWHomePage", "x121Address"]	
		
		elif 'computers' in type_out:
			
			header = ["accountExpires", "badPasswordTime", "badPwdCount", "cn", "codePage", "countryCode",
			          "dNSHostName", "dSCorePropagationData", "distinguishedName", "instanceType",
			          "isCriticalSystemObject", "lastLogoff", "lastLogon", "lastLogonTimestamp", "localPolicyFlags",
			          "logonCount", "msDFSR-ComputerReferenceBL", "msDS-SupportedEncryptionTypes", "name",
			          "objectCategory", "objectClass", "objectGUID", "objectSid", "operatingSystem",
			          "operatingSystemVersion", "primaryGroupID", "pwdLastSet", "rIDSetReferences", "sAMAccountName",
			          "sAMAccountType", "serverReferenceBL", "servicePrincipalName", "uSNChanged", "uSNCreated",
			          "userAccountControl", "whenChanged", "whenCreated"]
		return header
	
	
	def write_out(self, data='', filename='', type_out=''):
		header_w = False
		
		if 'users' in type_out:
			if not filename:
				filename = self.logger.LOG_DIR + '/ActiveDirectoryUsers.csv'
			header = self.get_headers(data, type_out)
			
		elif 'computers' in type_out:
			if not filename:
				filename = self.logger.LOG_DIR + '/ActiveDirectoryComputers.csv'
			header  = self.get_headers(data, type_out)		
				
		if not os.path.exists(filename):
			header_w = True
		with open(filename, "a",  encoding="utf-8", errors='ignore') as f:
			writer = csv.writer(f)
			if header_w:
				writer.writerow(header) 
			for l in data:
				writer.writerow(l)
	
	def attribute_parse(self, entries='', attrib_type=''):
		
		if not attrib_type:
			print('attribute type not set')
			self.logger.error('attribute type not set')
			sys.exit()
		elif not entries:
			print('no entries availble')
			self.logger.error('no entries availble')
			sys.exit()		
			
		for item in obj.ad.entries:
			attributes_ = []
			data = json.loads(item.entry_to_json())		
			
				
			if attrib_type == 'users':
			
			
				if 'accountExpires' in data['attributes']:
					#print(data['attributes']['accountExpires'][0])
					accountExpires = data['attributes']['accountExpires'][0]
				else:
					accountExpires = None
			
				if 'accountNameHistory' in data['attributes']:
					#print(data['attributes']['accountNameHistory'][0])
					accountNameHistory = data['attributes']['accountNameHistory'][0]
				else:
					accountNameHistory = None
			
				if 'aCSPolicyName' in data['attributes']:
					#print(data['attributes']['aCSPolicyName'][0])
					aCSPolicyName = data['attributes']['aCSPolicyName'][0]
				else:
					aCSPolicyName = None
			
				if 'adminCount' in data['attributes']:
					#print(data['attributes']['adminCount'][0])
					adminCount = data['attributes']['adminCount'][0]
				else:
					adminCount = None
			
				if 'adminDescription' in data['attributes']:
					#print(data['attributes']['adminDescription'][0])
					adminDescription = data['attributes']['adminDescription'][0]
				else:
					adminDescription = None
			
				if 'adminDisplayName' in data['attributes']:
					#print(data['attributes']['adminDisplayName'][0])
					adminDisplayName = data['attributes']['adminDisplayName'][0]
				else:
					adminDisplayName = None
			
				if 'allowedAttributes' in data['attributes']:
					#print(data['attributes']['allowedAttributes'][0])
					allowedAttributes = data['attributes']['allowedAttributes'][0]
				else:
					allowedAttributes = None
			
				if 'allowedAttributesEffective' in data['attributes']:
					#print(data['attributes']['allowedAttributesEffective'][0])
					allowedAttributesEffective = data['attributes']['allowedAttributesEffective'][0]
				else:
					allowedAttributesEffective = None
			
				if 'allowedChildClasses' in data['attributes']:
					#print(data['attributes']['allowedChildClasses'][0])
					allowedChildClasses = data['attributes']['allowedChildClasses'][0]
				else:
					allowedChildClasses = None
			
				if 'allowedChildClassesEffective' in data['attributes']:
					#print(data['attributes']['allowedChildClassesEffective'][0])
					allowedChildClassesEffective = data['attributes']['allowedChildClassesEffective'][0]
				else:
					allowedChildClassesEffective = None
			
				if 'altSecurityIdentities' in data['attributes']:
					#print(data['attributes']['altSecurityIdentities'][0])
					altSecurityIdentities = data['attributes']['altSecurityIdentities'][0]
				else:
					altSecurityIdentities = None
			
				if 'assistant' in data['attributes']:
					#print(data['attributes']['assistant'][0])
					assistant = data['attributes']['assistant'][0]
				else:
					assistant = None
			
				if 'badPasswordTime' in data['attributes']:
					#print(data['attributes']['badPasswordTime'][0])
					badPasswordTime = data['attributes']['badPasswordTime'][0]
				else:
					badPasswordTime = None
			
				if 'badPwdCount' in data['attributes']:
					#print(data['attributes']['badPwdCount'][0])
					badPwdCount = data['attributes']['badPwdCount'][0]
				else:
					badPwdCount = None
			
				if 'bridgeheadServerListBL' in data['attributes']:
					#print(data['attributes']['bridgeheadServerListBL'][0])
					bridgeheadServerListBL = data['attributes']['bridgeheadServerListBL'][0]
				else:
					bridgeheadServerListBL = None
			
				if 'c' in data['attributes']:
					#print(data['attributes']['c'][0])
					c = data['attributes']['c'][0]
				else:
					c = None
			
				if 'canonicalName' in data['attributes']:
					#print(data['attributes']['canonicalName'][0])
					canonicalName = data['attributes']['canonicalName'][0]
				else:
					canonicalName = None
			
				if 'cn' in data['attributes']:
					#print(data['attributes']['cn'][0])
					cn = data['attributes']['cn'][0]
				else:
					cn = None
			
				if 'co' in data['attributes']:
					#print(data['attributes']['co'][0])
					co = data['attributes']['co'][0]
				else:
					co = None
			
				if 'codePage' in data['attributes']:
					#print(data['attributes']['codePage'][0])
					codePage = data['attributes']['codePage'][0]
				else:
					codePage = None
			
				if 'comment' in data['attributes']:
					#print(data['attributes']['comment'][0])
					comment = data['attributes']['comment'][0]
				else:
					comment = None
			
				if 'company' in data['attributes']:
					#print(data['attributes']['company'][0])
					company = data['attributes']['company'][0]
				else:
					company = None
			
				if 'controlAccessRights' in data['attributes']:
					#print(data['attributes']['controlAccessRights'][0])
					controlAccessRights = data['attributes']['controlAccessRights'][0]
				else:
					controlAccessRights = None
			
				if 'countryCode' in data['attributes']:
					#print(data['attributes']['countryCode'][0])
					countryCode = data['attributes']['countryCode'][0]
				else:
					countryCode = None
			
				if 'createTimeStamp' in data['attributes']:
					#print(data['attributes']['createTimeStamp'][0])
					createTimeStamp = data['attributes']['createTimeStamp'][0]
				else:
					createTimeStamp = None
			
				if 'dBCSPwd' in data['attributes']:
					#print(data['attributes']['dBCSPwd'][0])
					dBCSPwd = data['attributes']['dBCSPwd'][0]
				else:
					dBCSPwd = None
			
				if 'defaultClassStore' in data['attributes']:
					#print(data['attributes']['defaultClassStore'][0])
					defaultClassStore = data['attributes']['defaultClassStore'][0]
				else:
					defaultClassStore = None
			
				if 'department' in data['attributes']:
					#print(data['attributes']['department'][0])
					department = data['attributes']['department'][0]
				else:
					department = None
			
				if 'description' in data['attributes']:
					#print(data['attributes']['description'][0])
					description = data['attributes']['description'][0]
				else:
					description = None
			
				if 'desktopProfile' in data['attributes']:
					#print(data['attributes']['desktopProfile'][0])
					desktopProfile = data['attributes']['desktopProfile'][0]
				else:
					desktopProfile = None
			
				if 'destinationIndicator' in data['attributes']:
					#print(data['attributes']['destinationIndicator'][0])
					destinationIndicator = data['attributes']['destinationIndicator'][0]
				else:
					destinationIndicator = None
			
				if 'directReports' in data['attributes']:
					#print(data['attributes']['directReports'][0])
					directReports = data['attributes']['directReports'][0]
				else:
					directReports = None
			
				if 'displayName' in data['attributes']:
					#print(data['attributes']['displayName'][0])
					displayName = data['attributes']['displayName'][0]
				else:
					displayName = None
			
				if 'displayNamePrintable' in data['attributes']:
					#print(data['attributes']['displayNamePrintable'][0])
					displayNamePrintable = data['attributes']['displayNamePrintable'][0]
				else:
					displayNamePrintable = None
			
				if 'distinguishedName' in data['attributes']:
					#print(data['attributes']['distinguishedName'][0])
					distinguishedName = data['attributes']['distinguishedName'][0]
				else:
					distinguishedName = None
			
				if 'division' in data['attributes']:
					#print(data['attributes']['division'][0])
					division = data['attributes']['division'][0]
				else:
					division = None
			
				if 'dSASignature' in data['attributes']:
					#print(data['attributes']['dSASignature'][0])
					dSASignature = data['attributes']['dSASignature'][0]
				else:
					dSASignature = None
			
				if 'dSCorePropagationData' in data['attributes']:
					#print(data['attributes']['dSCorePropagationData'][0])
					dSCorePropagationData = data['attributes']['dSCorePropagationData'][0]
				else:
					dSCorePropagationData = None
			
				if 'dynamicLDAPServer' in data['attributes']:
					#print(data['attributes']['dynamicLDAPServer'][0])
					dynamicLDAPServer = data['attributes']['dynamicLDAPServer'][0]
				else:
					dynamicLDAPServer = None
			
				if 'employeeID' in data['attributes']:
					#print(data['attributes']['employeeID'][0])
					employeeID = data['attributes']['employeeID'][0]
				else:
					employeeID = None
			
				if 'extensionName' in data['attributes']:
					#print(data['attributes']['extensionName'][0])
					extensionName = data['attributes']['extensionName'][0]
				else:
					extensionName = None
			
				if 'facsimileTelephoneNumber' in data['attributes']:
					#print(data['attributes']['facsimileTelephoneNumber'][0])
					facsimileTelephoneNumber = data['attributes']['facsimileTelephoneNumber'][0]
				else:
					facsimileTelephoneNumber = None
			
				if 'flags' in data['attributes']:
					#print(data['attributes']['flags'][0])
					flags = data['attributes']['flags'][0]
				else:
					flags = None
			
				if 'fromEntry' in data['attributes']:
					#print(data['attributes']['fromEntry'][0])
					fromEntry = data['attributes']['fromEntry'][0]
				else:
					fromEntry = None
			
				if 'frsComputerReferenceBL' in data['attributes']:
					#print(data['attributes']['frsComputerReferenceBL'][0])
					frsComputerReferenceBL = data['attributes']['frsComputerReferenceBL'][0]
				else:
					frsComputerReferenceBL = None
			
				if 'fRSMemberReferenceBL' in data['attributes']:
					#print(data['attributes']['fRSMemberReferenceBL'][0])
					fRSMemberReferenceBL = data['attributes']['fRSMemberReferenceBL'][0]
				else:
					fRSMemberReferenceBL = None
			
				if 'fSMORoleOwner' in data['attributes']:
					#print(data['attributes']['fSMORoleOwner'][0])
					fSMORoleOwner = data['attributes']['fSMORoleOwner'][0]
				else:
					fSMORoleOwner = None
			
				if 'garbageCollPeriod' in data['attributes']:
					#print(data['attributes']['garbageCollPeriod'][0])
					garbageCollPeriod = data['attributes']['garbageCollPeriod'][0]
				else:
					garbageCollPeriod = None
			
				if 'generationQualifier' in data['attributes']:
					#print(data['attributes']['generationQualifier'][0])
					generationQualifier = data['attributes']['generationQualifier'][0]
				else:
					generationQualifier = None
			
				if 'givenName' in data['attributes']:
					#print(data['attributes']['givenName'][0])
					givenName = data['attributes']['givenName'][0]
				else:
					givenName = None
			
				if 'groupMembershipSAM' in data['attributes']:
					#print(data['attributes']['groupMembershipSAM'][0])
					groupMembershipSAM = data['attributes']['groupMembershipSAM'][0]
				else:
					groupMembershipSAM = None
			
				if 'groupPriority' in data['attributes']:
					#print(data['attributes']['groupPriority'][0])
					groupPriority = data['attributes']['groupPriority'][0]
				else:
					groupPriority = None
			
				if 'groupsToIgnore' in data['attributes']:
					#print(data['attributes']['groupsToIgnore'][0])
					groupsToIgnore = data['attributes']['groupsToIgnore'][0]
				else:
					groupsToIgnore = None
			
				if 'homeDirectory' in data['attributes']:
					#print(data['attributes']['homeDirectory'][0])
					homeDirectory = data['attributes']['homeDirectory'][0]
				else:
					homeDirectory = None
			
				if 'homeDrive' in data['attributes']:
					#print(data['attributes']['homeDrive'][0])
					homeDrive = data['attributes']['homeDrive'][0]
				else:
					homeDrive = None
			
				if 'homePhone' in data['attributes']:
					#print(data['attributes']['homePhone'][0])
					homePhone = data['attributes']['homePhone'][0]
				else:
					homePhone = None
			
				if 'homePostalAddress' in data['attributes']:
					#print(data['attributes']['homePostalAddress'][0])
					homePostalAddress = data['attributes']['homePostalAddress'][0]
				else:
					homePostalAddress = None
			
				if 'info' in data['attributes']:
					#print(data['attributes']['info'][0])
					info = data['attributes']['info'][0]
				else:
					info = None
			
				if 'initials' in data['attributes']:
					#print(data['attributes']['initials'][0])
					initials = data['attributes']['initials'][0]
				else:
					initials = None
			
				if 'instanceType' in data['attributes']:
					#print(data['attributes']['instanceType'][0])
					instanceType = data['attributes']['instanceType'][0]
				else:
					instanceType = None
			
				if 'internationalISDNNumber' in data['attributes']:
					#print(data['attributes']['internationalISDNNumber'][0])
					internationalISDNNumber = data['attributes']['internationalISDNNumber'][0]
				else:
					internationalISDNNumber = None
			
				if 'ipPhone' in data['attributes']:
					#print(data['attributes']['ipPhone'][0])
					ipPhone = data['attributes']['ipPhone'][0]
				else:
					ipPhone = None
			
				if 'isCriticalSystemObject' in data['attributes']:
					#print(data['attributes']['isCriticalSystemObject'][0])
					isCriticalSystemObject = data['attributes']['isCriticalSystemObject'][0]
				else:
					isCriticalSystemObject = None
			
				if 'isDeleted' in data['attributes']:
					#print(data['attributes']['isDeleted'][0])
					isDeleted = data['attributes']['isDeleted'][0]
				else:
					isDeleted = None
			
				if 'isPrivilegeHolder' in data['attributes']:
					#print(data['attributes']['isPrivilegeHolder'][0])
					isPrivilegeHolder = data['attributes']['isPrivilegeHolder'][0]
				else:
					isPrivilegeHolder = None
			
				if 'l' in data['attributes']:
					#print(data['attributes']['l'][0])
					l = data['attributes']['l'][0]
				else:
					l = None
			
				if 'lastKnownParent' in data['attributes']:
					#print(data['attributes']['lastKnownParent'][0])
					lastKnownParent = data['attributes']['lastKnownParent'][0]
				else:
					lastKnownParent = None
			
				if 'lastLogoff' in data['attributes']:
					#print(data['attributes']['lastLogoff'][0])
					lastLogoff = data['attributes']['lastLogoff'][0]
				else:
					lastLogoff = None
			
				if 'lastLogon' in data['attributes']:
					#print(data['attributes']['lastLogon'][0])
					lastLogon = data['attributes']['lastLogon'][0]
				else:
					lastLogon = None
			
				if 'legacyExchangeDN' in data['attributes']:
					#print(data['attributes']['legacyExchangeDN'][0])
					legacyExchangeDN = data['attributes']['legacyExchangeDN'][0]
				else:
					legacyExchangeDN = None
			
				if 'lmPwdHistory' in data['attributes']:
					#print(data['attributes']['lmPwdHistory'][0])
					lmPwdHistory = data['attributes']['lmPwdHistory'][0]
				else:
					lmPwdHistory = None
			
				if 'localeID' in data['attributes']:
					#print(data['attributes']['localeID'][0])
					localeID = data['attributes']['localeID'][0]
				else:
					localeID = None
			
				if 'lockoutTime' in data['attributes']:
					#print(data['attributes']['lockoutTime'][0])
					lockoutTime = data['attributes']['lockoutTime'][0]
				else:
					lockoutTime = None
			
				if 'logonCount' in data['attributes']:
					#print(data['attributes']['logonCount'][0])
					logonCount = data['attributes']['logonCount'][0]
				else:
					logonCount = None
			
				if 'logonHours' in data['attributes']:
					#print(data['attributes']['logonHours'][0])
					logonHours = data['attributes']['logonHours'][0]
				else:
					logonHours = None
			
				if 'logonWorkstation' in data['attributes']:
					#print(data['attributes']['logonWorkstation'][0])
					logonWorkstation = data['attributes']['logonWorkstation'][0]
				else:
					logonWorkstation = None
			
				if 'mail' in data['attributes']:
					#print(data['attributes']['mail'][0])
					mail = data['attributes']['mail'][0]
				else:
					mail = None
			
				if 'managedObjects' in data['attributes']:
					#print(data['attributes']['managedObjects'][0])
					managedObjects = data['attributes']['managedObjects'][0]
				else:
					managedObjects = None
			
				if 'manager' in data['attributes']:
					#print(data['attributes']['manager'][0])
					manager = data['attributes']['manager'][0]
				else:
					manager = None
			
				if 'masteredBy' in data['attributes']:
					#print(data['attributes']['masteredBy'][0])
					masteredBy = data['attributes']['masteredBy'][0]
				else:
					masteredBy = None
			
				if 'maxStorage' in data['attributes']:
					#print(data['attributes']['maxStorage'][0])
					maxStorage = data['attributes']['maxStorage'][0]
				else:
					maxStorage = None
			
				if 'memberOf' in data['attributes']:
					#print(data['attributes']['memberOf'][0])
					memberOf = data['attributes']['memberOf'][0]
				else:
					memberOf = None
			
				if 'mhsORAddress' in data['attributes']:
					#print(data['attributes']['mhsORAddress'][0])
					mhsORAddress = data['attributes']['mhsORAddress'][0]
				else:
					mhsORAddress = None
			
				if 'middleName' in data['attributes']:
					#print(data['attributes']['middleName'][0])
					middleName = data['attributes']['middleName'][0]
				else:
					middleName = None
			
				if 'mobile' in data['attributes']:
					#print(data['attributes']['mobile'][0])
					mobile = data['attributes']['mobile'][0]
				else:
					mobile = None
			
				if 'modifyTimeStamp' in data['attributes']:
					#print(data['attributes']['modifyTimeStamp'][0])
					modifyTimeStamp = data['attributes']['modifyTimeStamp'][0]
				else:
					modifyTimeStamp = None
			
				if 'mS-DS-ConsistencyChildCount' in data['attributes']:
					#print(data['attributes']['mS-DS-ConsistencyChildCount'][0])
					mS_DS_ConsistencyChildCount = data['attributes']['mS-DS-ConsistencyChildCount'][0]
				else:
					mS_DS_ConsistencyChildCount = None
			
				if 'mS-DS-ConsistencyGuid' in data['attributes']:
					#print(data['attributes']['mS-DS-ConsistencyGuid'][0])
					mS_DS_ConsistencyGuid = data['attributes']['mS-DS-ConsistencyGuid'][0]
				else:
					mS_DS_ConsistencyGuid = None
			
				if 'mS-DS-CreatorSID' in data['attributes']:
					#print(data['attributes']['mS-DS-CreatorSID'][0])
					mS_DS_CreatorSID = data['attributes']['mS-DS-CreatorSID'][0]
				else:
					mS_DS_CreatorSID = None
			
				if 'mSMQDigests' in data['attributes']:
					#print(data['attributes']['mSMQDigests'][0])
					mSMQDigests = data['attributes']['mSMQDigests'][0]
				else:
					mSMQDigests = None
			
				if 'mSMQDigestsMig' in data['attributes']:
					#print(data['attributes']['mSMQDigestsMig'][0])
					mSMQDigestsMig = data['attributes']['mSMQDigestsMig'][0]
				else:
					mSMQDigestsMig = None
			
				if 'mSMQSignCertificates' in data['attributes']:
					#print(data['attributes']['mSMQSignCertificates'][0])
					mSMQSignCertificates = data['attributes']['mSMQSignCertificates'][0]
				else:
					mSMQSignCertificates = None
			
				if 'mSMQSignCertificatesMig' in data['attributes']:
					#print(data['attributes']['mSMQSignCertificatesMig'][0])
					mSMQSignCertificatesMig = data['attributes']['mSMQSignCertificatesMig'][0]
				else:
					mSMQSignCertificatesMig = None
			
				if 'msNPAllowDialin' in data['attributes']:
					#print(data['attributes']['msNPAllowDialin'][0])
					msNPAllowDialin = data['attributes']['msNPAllowDialin'][0]
				else:
					msNPAllowDialin = None
			
				if 'msNPCallingStationID' in data['attributes']:
					#print(data['attributes']['msNPCallingStationID'][0])
					msNPCallingStationID = data['attributes']['msNPCallingStationID'][0]
				else:
					msNPCallingStationID = None
			
				if 'msNPSavedCallingStationID' in data['attributes']:
					#print(data['attributes']['msNPSavedCallingStationID'][0])
					msNPSavedCallingStationID = data['attributes']['msNPSavedCallingStationID'][0]
				else:
					msNPSavedCallingStationID = None
			
				if 'msRADIUSCallbackNumber' in data['attributes']:
					#print(data['attributes']['msRADIUSCallbackNumber'][0])
					msRADIUSCallbackNumber = data['attributes']['msRADIUSCallbackNumber'][0]
				else:
					msRADIUSCallbackNumber = None
			
				if 'msRADIUSFramedIPAddress' in data['attributes']:
					#print(data['attributes']['msRADIUSFramedIPAddress'][0])
					msRADIUSFramedIPAddress = data['attributes']['msRADIUSFramedIPAddress'][0]
				else:
					msRADIUSFramedIPAddress = None
			
				if 'msRADIUSFramedRoute' in data['attributes']:
					#print(data['attributes']['msRADIUSFramedRoute'][0])
					msRADIUSFramedRoute = data['attributes']['msRADIUSFramedRoute'][0]
				else:
					msRADIUSFramedRoute = None
			
				if 'msRADIUSServiceType' in data['attributes']:
					#print(data['attributes']['msRADIUSServiceType'][0])
					msRADIUSServiceType = data['attributes']['msRADIUSServiceType'][0]
				else:
					msRADIUSServiceType = None
			
				if 'msRASSavedCallbackNumber' in data['attributes']:
					#print(data['attributes']['msRASSavedCallbackNumber'][0])
					msRASSavedCallbackNumber = data['attributes']['msRASSavedCallbackNumber'][0]
				else:
					msRASSavedCallbackNumber = None
			
				if 'msRASSavedFramedIPAddress' in data['attributes']:
					#print(data['attributes']['msRASSavedFramedIPAddress'][0])
					msRASSavedFramedIPAddress = data['attributes']['msRASSavedFramedIPAddress'][0]
				else:
					msRASSavedFramedIPAddress = None
			
				if 'msRASSavedFramedRoute' in data['attributes']:
					#print(data['attributes']['msRASSavedFramedRoute'][0])
					msRASSavedFramedRoute = data['attributes']['msRASSavedFramedRoute'][0]
				else:
					msRASSavedFramedRoute = None
			
				if 'name' in data['attributes']:
					#print(data['attributes']['name'][0])
					name = data['attributes']['name'][0]
				else:
					name = None
			
				if 'netbootSCPBL' in data['attributes']:
					#print(data['attributes']['netbootSCPBL'][0])
					netbootSCPBL = data['attributes']['netbootSCPBL'][0]
				else:
					netbootSCPBL = None
			
				if 'networkAddress' in data['attributes']:
					#print(data['attributes']['networkAddress'][0])
					networkAddress = data['attributes']['networkAddress'][0]
				else:
					networkAddress = None
			
				if 'nonSecurityMemberBL' in data['attributes']:
					#print(data['attributes']['nonSecurityMemberBL'][0])
					nonSecurityMemberBL = data['attributes']['nonSecurityMemberBL'][0]
				else:
					nonSecurityMemberBL = None
			
				if 'ntPwdHistory' in data['attributes']:
					#print(data['attributes']['ntPwdHistory'][0])
					ntPwdHistory = data['attributes']['ntPwdHistory'][0]
				else:
					ntPwdHistory = None
			
				if 'nTSecurityDescriptor' in data['attributes']:
					#print(data['attributes']['nTSecurityDescriptor'][0])
					nTSecurityDescriptor = data['attributes']['nTSecurityDescriptor'][0]
				else:
					nTSecurityDescriptor = None
			
				if 'o' in data['attributes']:
					#print(data['attributes']['o'][0])
					o = data['attributes']['o'][0]
				else:
					o = None
			
				if 'objectCategory' in data['attributes']:
					#print(data['attributes']['objectCategory'][0])
					objectCategory = data['attributes']['objectCategory'][0]
				else:
					objectCategory = None
			
				if 'objectClass' in data['attributes']:
					#print(data['attributes']['objectClass'][0])
					objectClass = data['attributes']['objectClass'][0]
				else:
					objectClass = None
			
				if 'objectGUID' in data['attributes']:
					#print(data['attributes']['objectGUID'][0])
					objectGUID = data['attributes']['objectGUID'][0]
				else:
					objectGUID = None
			
				if 'objectSid' in data['attributes']:
					#print(data['attributes']['objectSid'][0])
					objectSid = data['attributes']['objectSid'][0]
				else:
					objectSid = None
			
				if 'objectVersion' in data['attributes']:
					#print(data['attributes']['objectVersion'][0])
					objectVersion = data['attributes']['objectVersion'][0]
				else:
					objectVersion = None
			
				if 'operatorCount' in data['attributes']:
					#print(data['attributes']['operatorCount'][0])
					operatorCount = data['attributes']['operatorCount'][0]
				else:
					operatorCount = None
			
				if 'otherFacsimileTelephoneNumber' in data['attributes']:
					#print(data['attributes']['otherFacsimileTelephoneNumber'][0])
					otherFacsimileTelephoneNumber = data['attributes']['otherFacsimileTelephoneNumber'][0]
				else:
					otherFacsimileTelephoneNumber = None
			
				if 'otherHomePhone' in data['attributes']:
					#print(data['attributes']['otherHomePhone'][0])
					otherHomePhone = data['attributes']['otherHomePhone'][0]
				else:
					otherHomePhone = None
			
				if 'otherIpPhone' in data['attributes']:
					#print(data['attributes']['otherIpPhone'][0])
					otherIpPhone = data['attributes']['otherIpPhone'][0]
				else:
					otherIpPhone = None
			
				if 'otherLoginWorkstations' in data['attributes']:
					#print(data['attributes']['otherLoginWorkstations'][0])
					otherLoginWorkstations = data['attributes']['otherLoginWorkstations'][0]
				else:
					otherLoginWorkstations = None
			
				if 'otherMailbox' in data['attributes']:
					#print(data['attributes']['otherMailbox'][0])
					otherMailbox = data['attributes']['otherMailbox'][0]
				else:
					otherMailbox = None
			
				if 'otherMobile' in data['attributes']:
					#print(data['attributes']['otherMobile'][0])
					otherMobile = data['attributes']['otherMobile'][0]
				else:
					otherMobile = None
			
				if 'otherPager' in data['attributes']:
					#print(data['attributes']['otherPager'][0])
					otherPager = data['attributes']['otherPager'][0]
				else:
					otherPager = None
			
				if 'otherTelephone' in data['attributes']:
					#print(data['attributes']['otherTelephone'][0])
					otherTelephone = data['attributes']['otherTelephone'][0]
				else:
					otherTelephone = None
			
				if 'otherWellKnownObjects' in data['attributes']:
					#print(data['attributes']['otherWellKnownObjects'][0])
					otherWellKnownObjects = data['attributes']['otherWellKnownObjects'][0]
				else:
					otherWellKnownObjects = None
			
				if 'ou' in data['attributes']:
					#print(data['attributes']['ou'][0])
					ou = data['attributes']['ou'][0]
				else:
					ou = None
			
				if 'pager' in data['attributes']:
					#print(data['attributes']['pager'][0])
					pager = data['attributes']['pager'][0]
				else:
					pager = None
			
				if 'partialAttributeDeletionList' in data['attributes']:
					#print(data['attributes']['partialAttributeDeletionList'][0])
					partialAttributeDeletionList = data['attributes']['partialAttributeDeletionList'][0]
				else:
					partialAttributeDeletionList = None
			
				if 'partialAttributeSet' in data['attributes']:
					#print(data['attributes']['partialAttributeSet'][0])
					partialAttributeSet = data['attributes']['partialAttributeSet'][0]
				else:
					partialAttributeSet = None
			
				if 'personalTitle' in data['attributes']:
					#print(data['attributes']['personalTitle'][0])
					personalTitle = data['attributes']['personalTitle'][0]
				else:
					personalTitle = None
			
				if 'physicalDeliveryOfficeName' in data['attributes']:
					#print(data['attributes']['physicalDeliveryOfficeName'][0])
					physicalDeliveryOfficeName = data['attributes']['physicalDeliveryOfficeName'][0]
				else:
					physicalDeliveryOfficeName = None
			
				if 'possibleInferiors' in data['attributes']:
					#print(data['attributes']['possibleInferiors'][0])
					possibleInferiors = data['attributes']['possibleInferiors'][0]
				else:
					possibleInferiors = None
			
				if 'postalAddress' in data['attributes']:
					#print(data['attributes']['postalAddress'][0])
					postalAddress = data['attributes']['postalAddress'][0]
				else:
					postalAddress = None
			
				if 'postalCode' in data['attributes']:
					#print(data['attributes']['postalCode'][0])
					postalCode = data['attributes']['postalCode'][0]
				else:
					postalCode = None
			
				if 'postOfficeBox' in data['attributes']:
					#print(data['attributes']['postOfficeBox'][0])
					postOfficeBox = data['attributes']['postOfficeBox'][0]
				else:
					postOfficeBox = None
			
				if 'preferredDeliveryMethod' in data['attributes']:
					#print(data['attributes']['preferredDeliveryMethod'][0])
					preferredDeliveryMethod = data['attributes']['preferredDeliveryMethod'][0]
				else:
					preferredDeliveryMethod = None
			
				if 'preferredOU' in data['attributes']:
					#print(data['attributes']['preferredOU'][0])
					preferredOU = data['attributes']['preferredOU'][0]
				else:
					preferredOU = None
			
				if 'primaryGroupID' in data['attributes']:
					#print(data['attributes']['primaryGroupID'][0])
					primaryGroupID = data['attributes']['primaryGroupID'][0]
				else:
					primaryGroupID = None
			
				if 'primaryInternationalISDNNumber' in data['attributes']:
					#print(data['attributes']['primaryInternationalISDNNumber'][0])
					primaryInternationalISDNNumber = data['attributes']['primaryInternationalISDNNumber'][0]
				else:
					primaryInternationalISDNNumber = None
			
				if 'primaryTelexNumber' in data['attributes']:
					#print(data['attributes']['primaryTelexNumber'][0])
					primaryTelexNumber = data['attributes']['primaryTelexNumber'][0]
				else:
					primaryTelexNumber = None
			
				if 'profilePath' in data['attributes']:
					#print(data['attributes']['profilePath'][0])
					profilePath = data['attributes']['profilePath'][0]
				else:
					profilePath = None
			
				if 'proxiedObjectName' in data['attributes']:
					#print(data['attributes']['proxiedObjectName'][0])
					proxiedObjectName = data['attributes']['proxiedObjectName'][0]
				else:
					proxiedObjectName = None
			
				if 'proxyAddresses' in data['attributes']:
					#print(data['attributes']['proxyAddresses'][0])
					proxyAddresses = data['attributes']['proxyAddresses'][0]
				else:
					proxyAddresses = None
			
				if 'pwdLastSet' in data['attributes']:
					#print(data['attributes']['pwdLastSet'][0])
					pwdLastSet = data['attributes']['pwdLastSet'][0]
				else:
					pwdLastSet = None
			
				if 'queryPolicyBL' in data['attributes']:
					#print(data['attributes']['queryPolicyBL'][0])
					queryPolicyBL = data['attributes']['queryPolicyBL'][0]
				else:
					queryPolicyBL = None
			
				if 'registeredAddress' in data['attributes']:
					#print(data['attributes']['registeredAddress'][0])
					registeredAddress = data['attributes']['registeredAddress'][0]
				else:
					registeredAddress = None
			
				if 'replPropertyMetaData' in data['attributes']:
					#print(data['attributes']['replPropertyMetaData'][0])
					replPropertyMetaData = data['attributes']['replPropertyMetaData'][0]
				else:
					replPropertyMetaData = None
			
				if 'replUpToDateVector' in data['attributes']:
					#print(data['attributes']['replUpToDateVector'][0])
					replUpToDateVector = data['attributes']['replUpToDateVector'][0]
				else:
					replUpToDateVector = None
			
				if 'repsFrom' in data['attributes']:
					#print(data['attributes']['repsFrom'][0])
					repsFrom = data['attributes']['repsFrom'][0]
				else:
					repsFrom = None
			
				if 'repsTo' in data['attributes']:
					#print(data['attributes']['repsTo'][0])
					repsTo = data['attributes']['repsTo'][0]
				else:
					repsTo = None
			
				if 'revision' in data['attributes']:
					#print(data['attributes']['revision'][0])
					revision = data['attributes']['revision'][0]
				else:
					revision = None
			
				if 'rid' in data['attributes']:
					#print(data['attributes']['rid'][0])
					rid = data['attributes']['rid'][0]
				else:
					rid = None
			
				if 'sAMAccountName' in data['attributes']:
					#print(data['attributes']['sAMAccountName'][0])
					sAMAccountName = data['attributes']['sAMAccountName'][0]
				else:
					sAMAccountName = None
			
				if 'sAMAccountType' in data['attributes']:
					#print(data['attributes']['sAMAccountType'][0])
					sAMAccountType = data['attributes']['sAMAccountType'][0]
				else:
					sAMAccountType = None
			
				if 'scriptPath' in data['attributes']:
					#print(data['attributes']['scriptPath'][0])
					scriptPath = data['attributes']['scriptPath'][0]
				else:
					scriptPath = None
			
				if 'sDRightsEffective' in data['attributes']:
					#print(data['attributes']['sDRightsEffective'][0])
					sDRightsEffective = data['attributes']['sDRightsEffective'][0]
				else:
					sDRightsEffective = None
			
				if 'securityIdentifier' in data['attributes']:
					#print(data['attributes']['securityIdentifier'][0])
					securityIdentifier = data['attributes']['securityIdentifier'][0]
				else:
					securityIdentifier = None
			
				if 'seeAlso' in data['attributes']:
					#print(data['attributes']['seeAlso'][0])
					seeAlso = data['attributes']['seeAlso'][0]
				else:
					seeAlso = None
			
				if 'serverReferenceBL' in data['attributes']:
					#print(data['attributes']['serverReferenceBL'][0])
					serverReferenceBL = data['attributes']['serverReferenceBL'][0]
				else:
					serverReferenceBL = None
			
				if 'servicePrincipalName' in data['attributes']:
					#print(data['attributes']['servicePrincipalName'][0])
					servicePrincipalName = data['attributes']['servicePrincipalName'][0]
				else:
					servicePrincipalName = None
			
				if 'showInAddressBook' in data['attributes']:
					#print(data['attributes']['showInAddressBook'][0])
					showInAddressBook = data['attributes']['showInAddressBook'][0]
				else:
					showInAddressBook = None
			
				if 'showInAdvancedViewOnly' in data['attributes']:
					#print(data['attributes']['showInAdvancedViewOnly'][0])
					showInAdvancedViewOnly = data['attributes']['showInAdvancedViewOnly'][0]
				else:
					showInAdvancedViewOnly = None
			
				if 'sIDHistory' in data['attributes']:
					#print(data['attributes']['sIDHistory'][0])
					sIDHistory = data['attributes']['sIDHistory'][0]
				else:
					sIDHistory = None
			
				if 'siteObjectBL' in data['attributes']:
					#print(data['attributes']['siteObjectBL'][0])
					siteObjectBL = data['attributes']['siteObjectBL'][0]
				else:
					siteObjectBL = None
			
				if 'sn' in data['attributes']:
					#print(data['attributes']['sn'][0])
					sn = data['attributes']['sn'][0]
				else:
					sn = None
			
				if 'st' in data['attributes']:
					#print(data['attributes']['st'][0])
					st = data['attributes']['st'][0]
				else:
					st = None
			
				if 'street' in data['attributes']:
					#print(data['attributes']['street'][0])
					street = data['attributes']['street'][0]
				else:
					street = None
			
				if 'streetAddress' in data['attributes']:
					#print(data['attributes']['streetAddress'][0])
					streetAddress = data['attributes']['streetAddress'][0]
				else:
					streetAddress = None
			
				if 'subRefs' in data['attributes']:
					#print(data['attributes']['subRefs'][0])
					subRefs = data['attributes']['subRefs'][0]
				else:
					subRefs = None
			
				if 'subSchemaSubEntry' in data['attributes']:
					#print(data['attributes']['subSchemaSubEntry'][0])
					subSchemaSubEntry = data['attributes']['subSchemaSubEntry'][0]
				else:
					subSchemaSubEntry = None
			
				if 'supplementalCredentials' in data['attributes']:
					#print(data['attributes']['supplementalCredentials'][0])
					supplementalCredentials = data['attributes']['supplementalCredentials'][0]
				else:
					supplementalCredentials = None
			
				if 'systemFlags' in data['attributes']:
					#print(data['attributes']['systemFlags'][0])
					systemFlags = data['attributes']['systemFlags'][0]
				else:
					systemFlags = None
			
				if 'telephoneNumber' in data['attributes']:
					#print(data['attributes']['telephoneNumber'][0])
					telephoneNumber = data['attributes']['telephoneNumber'][0]
				else:
					telephoneNumber = None
			
				if 'teletexTerminalIdentifier' in data['attributes']:
					#print(data['attributes']['teletexTerminalIdentifier'][0])
					teletexTerminalIdentifier = data['attributes']['teletexTerminalIdentifier'][0]
				else:
					teletexTerminalIdentifier = None
			
				if 'telexNumber' in data['attributes']:
					#print(data['attributes']['telexNumber'][0])
					telexNumber = data['attributes']['telexNumber'][0]
				else:
					telexNumber = None
			
				if 'terminalServer' in data['attributes']:
					#print(data['attributes']['terminalServer'][0])
					terminalServer = data['attributes']['terminalServer'][0]
				else:
					terminalServer = None
			
				if 'textEncodedORAddress' in data['attributes']:
					#print(data['attributes']['textEncodedORAddress'][0])
					textEncodedORAddress = data['attributes']['textEncodedORAddress'][0]
				else:
					textEncodedORAddress = None
			
				if 'thumbnailLogo' in data['attributes']:
					#print(data['attributes']['thumbnailLogo'][0])
					thumbnailLogo = data['attributes']['thumbnailLogo'][0]
				else:
					thumbnailLogo = None
			
				if 'thumbnailPhoto' in data['attributes']:
					#print(data['attributes']['thumbnailPhoto'][0])
					thumbnailPhoto = data['attributes']['thumbnailPhoto'][0]
				else:
					thumbnailPhoto = None
			
				if 'title' in data['attributes']:
					#print(data['attributes']['title'][0])
					title = data['attributes']['title'][0]
				else:
					title = None
			
				if 'tokenGroups' in data['attributes']:
					#print(data['attributes']['tokenGroups'][0])
					tokenGroups = data['attributes']['tokenGroups'][0]
				else:
					tokenGroups = None
			
				if 'tokenGroupsGlobalAndUniversal' in data['attributes']:
					#print(data['attributes']['tokenGroupsGlobalAndUniversal'][0])
					tokenGroupsGlobalAndUniversal = data['attributes']['tokenGroupsGlobalAndUniversal'][0]
				else:
					tokenGroupsGlobalAndUniversal = None
			
				if 'tokenGroupsNoGCAcceptable' in data['attributes']:
					#print(data['attributes']['tokenGroupsNoGCAcceptable'][0])
					tokenGroupsNoGCAcceptable = data['attributes']['tokenGroupsNoGCAcceptable'][0]
				else:
					tokenGroupsNoGCAcceptable = None
			
				if 'unicodePwd' in data['attributes']:
					#print(data['attributes']['unicodePwd'][0])
					unicodePwd = data['attributes']['unicodePwd'][0]
				else:
					unicodePwd = None
			
				if 'url' in data['attributes']:
					#print(data['attributes']['url'][0])
					url = data['attributes']['url'][0]
				else:
					url = None
			
				if 'userAccountControl' in data['attributes']:
					#print(data['attributes']['userAccountControl'][0])
					userAccountControl = data['attributes']['userAccountControl'][0]
				else:
					userAccountControl = None
			
				if 'userCert' in data['attributes']:
					#print(data['attributes']['userCert'][0])
					userCert = data['attributes']['userCert'][0]
				else:
					userCert = None
			
				if 'userCertificate' in data['attributes']:
					#print(data['attributes']['userCertificate'][0])
					userCertificate = data['attributes']['userCertificate'][0]
				else:
					userCertificate = None
			
				if 'userParameters' in data['attributes']:
					#print(data['attributes']['userParameters'][0])
					userParameters = data['attributes']['userParameters'][0]
				else:
					userParameters = None
			
				if 'userPassword' in data['attributes']:
					#print(data['attributes']['userPassword'][0])
					userPassword = data['attributes']['userPassword'][0]
				else:
					userPassword = None
			
				if 'userPrincipalName' in data['attributes']:
					#print(data['attributes']['userPrincipalName'][0])
					userPrincipalName = data['attributes']['userPrincipalName'][0]
				else:
					userPrincipalName = None
			
				if 'userSharedFolder' in data['attributes']:
					#print(data['attributes']['userSharedFolder'][0])
					userSharedFolder = data['attributes']['userSharedFolder'][0]
				else:
					userSharedFolder = None
			
				if 'userSharedFolderOther' in data['attributes']:
					#print(data['attributes']['userSharedFolderOther'][0])
					userSharedFolderOther = data['attributes']['userSharedFolderOther'][0]
				else:
					userSharedFolderOther = None
			
				if 'userSMIMECertificate' in data['attributes']:
					#print(data['attributes']['userSMIMECertificate'][0])
					userSMIMECertificate = data['attributes']['userSMIMECertificate'][0]
				else:
					userSMIMECertificate = None
			
				if 'userWorkstations' in data['attributes']:
					#print(data['attributes']['userWorkstations'][0])
					userWorkstations = data['attributes']['userWorkstations'][0]
				else:
					userWorkstations = None
			
				if 'uSNChanged' in data['attributes']:
					#print(data['attributes']['uSNChanged'][0])
					uSNChanged = data['attributes']['uSNChanged'][0]
				else:
					uSNChanged = None
			
				if 'uSNCreated' in data['attributes']:
					#print(data['attributes']['uSNCreated'][0])
					uSNCreated = data['attributes']['uSNCreated'][0]
				else:
					uSNCreated = None
			
				if 'uSNDSALastObjRemoved' in data['attributes']:
					#print(data['attributes']['uSNDSALastObjRemoved'][0])
					uSNDSALastObjRemoved = data['attributes']['uSNDSALastObjRemoved'][0]
				else:
					uSNDSALastObjRemoved = None
			
				if 'USNIntersite' in data['attributes']:
					#print(data['attributes']['USNIntersite'][0])
					USNIntersite = data['attributes']['USNIntersite'][0]
				else:
					USNIntersite = None
			
				if 'uSNLastObjRem' in data['attributes']:
					#print(data['attributes']['uSNLastObjRem'][0])
					uSNLastObjRem = data['attributes']['uSNLastObjRem'][0]
				else:
					uSNLastObjRem = None
			
				if 'uSNSource' in data['attributes']:
					#print(data['attributes']['uSNSource'][0])
					uSNSource = data['attributes']['uSNSource'][0]
				else:
					uSNSource = None
			
				if 'wbemPath' in data['attributes']:
					#print(data['attributes']['wbemPath'][0])
					wbemPath = data['attributes']['wbemPath'][0]
				else:
					wbemPath = None
			
				if 'wellKnownObjects' in data['attributes']:
					#print(data['attributes']['wellKnownObjects'][0])
					wellKnownObjects = data['attributes']['wellKnownObjects'][0]
				else:
					wellKnownObjects = None
			
				if 'whenChanged' in data['attributes']:
					#print(data['attributes']['whenChanged'][0])
					whenChanged = data['attributes']['whenChanged'][0]
				else:
					whenChanged = None
			
				if 'whenCreated' in data['attributes']:
					#print(data['attributes']['whenCreated'][0])
					whenCreated = data['attributes']['whenCreated'][0]
				else:
					whenCreated = None
			
				if 'wWWHomePage' in data['attributes']:
					#print(data['attributes']['wWWHomePage'][0])
					wWWHomePage = data['attributes']['wWWHomePage'][0]
				else:
					wWWHomePage = None
			
				if 'x121Address' in data['attributes']:
					#print(data['attributes']['x121Address'][0])
					x121Address = data['attributes']['x121Address'][0]
				else:
					x121Address = None
				
				
				attributes_.append((accountExpires, accountNameHistory, aCSPolicyName, adminCount, adminDescription,
				                    adminDisplayName, allowedAttributes, allowedAttributesEffective, allowedChildClasses,
				                    allowedChildClassesEffective, altSecurityIdentities, assistant, badPasswordTime,
				                    badPwdCount, bridgeheadServerListBL, c, canonicalName, cn, co, codePage, comment,
				                    company, controlAccessRights, countryCode, createTimeStamp, dBCSPwd, defaultClassStore,
				                    department, description, desktopProfile, destinationIndicator, directReports,
				                    displayName, displayNamePrintable, distinguishedName, division, dSASignature,
				                    dSCorePropagationData, dynamicLDAPServer, employeeID, extensionName,
				                    facsimileTelephoneNumber, flags, fromEntry, frsComputerReferenceBL, fRSMemberReferenceBL,
				                    fSMORoleOwner, garbageCollPeriod, generationQualifier, givenName, groupMembershipSAM,
				                    groupPriority, groupsToIgnore, homeDirectory, homeDrive, homePhone, homePostalAddress,
				                    info, initials, instanceType, internationalISDNNumber, ipPhone, isCriticalSystemObject,
				                    isDeleted, isPrivilegeHolder, l, lastKnownParent, lastLogoff, lastLogon,
				                    legacyExchangeDN, lmPwdHistory, localeID, lockoutTime, logonCount, logonHours,
				                    logonWorkstation, mail, managedObjects, manager, masteredBy, maxStorage, memberOf,
				                    mhsORAddress, middleName, mobile, modifyTimeStamp, mS_DS_ConsistencyChildCount,
				                    mS_DS_ConsistencyGuid, mS_DS_CreatorSID, mSMQDigests, mSMQDigestsMig,
				                    mSMQSignCertificates, mSMQSignCertificatesMig, msNPAllowDialin, msNPCallingStationID,
				                    msNPSavedCallingStationID, msRADIUSCallbackNumber, msRADIUSFramedIPAddress,
				                    msRADIUSFramedRoute, msRADIUSServiceType, msRASSavedCallbackNumber,
				                    msRASSavedFramedIPAddress, msRASSavedFramedRoute, name, netbootSCPBL, networkAddress,
				                    nonSecurityMemberBL, ntPwdHistory, nTSecurityDescriptor, o, objectCategory, objectClass,
				                    objectGUID, objectSid, objectVersion, operatorCount, otherFacsimileTelephoneNumber,
				                    otherHomePhone, otherIpPhone, otherLoginWorkstations, otherMailbox, otherMobile,
				                    otherPager, otherTelephone, otherWellKnownObjects, ou, pager,
				                    partialAttributeDeletionList, partialAttributeSet, personalTitle,
				                    physicalDeliveryOfficeName, possibleInferiors, postalAddress, postalCode, postOfficeBox,
				                    preferredDeliveryMethod, preferredOU, primaryGroupID, primaryInternationalISDNNumber,
				                    primaryTelexNumber, profilePath, proxiedObjectName, proxyAddresses, pwdLastSet,
				                    queryPolicyBL, registeredAddress, replPropertyMetaData, replUpToDateVector, repsFrom,
				                    repsTo, revision, rid, sAMAccountName, sAMAccountType, scriptPath, sDRightsEffective,
				                    securityIdentifier, seeAlso, serverReferenceBL, servicePrincipalName, showInAddressBook,
				                    showInAdvancedViewOnly, sIDHistory, siteObjectBL, sn, st, street, streetAddress,
				                    subRefs, subSchemaSubEntry, supplementalCredentials, systemFlags, telephoneNumber,
				                    teletexTerminalIdentifier, telexNumber, terminalServer, textEncodedORAddress,
				                    thumbnailLogo, thumbnailPhoto, title, tokenGroups, tokenGroupsGlobalAndUniversal,
				                    tokenGroupsNoGCAcceptable, unicodePwd, url, userAccountControl, userCert,
				                    userCertificate, userParameters, userPassword, userPrincipalName, userSharedFolder,
				                    userSharedFolderOther, userSMIMECertificate, userWorkstations, uSNChanged, uSNCreated,
				                    uSNDSALastObjRemoved, USNIntersite, uSNLastObjRem, uSNSource, wbemPath,
				                    wellKnownObjects, whenChanged, whenCreated, wWWHomePage, x121Address))
			
			
				self.write_out(attributes_, '', attrib_type)
			elif attrib_type == 'computers':
			
				if 'accountExpires' in data['attributes']:
					#print(data['attributes']['accountExpires'][0])
					accountExpires = data['attributes']['accountExpires'][0]
				else:
					accountExpires = None
			
				if 'badPasswordTime' in data['attributes']:
					#print(data['attributes']['badPasswordTime'][0])
					badPasswordTime = data['attributes']['badPasswordTime'][0]
				else:
					badPasswordTime = None
			
				if 'badPwdCount' in data['attributes']:
					#print(data['attributes']['badPwdCount'][0])
					badPwdCount = data['attributes']['badPwdCount'][0]
				else:
					badPwdCount = None
			
				if 'cn' in data['attributes']:
					#print(data['attributes']['cn'][0])
					cn = data['attributes']['cn'][0]
				else:
					cn = None
			
				if 'codePage' in data['attributes']:
					#print(data['attributes']['codePage'][0])
					codePage = data['attributes']['codePage'][0]
				else:
					codePage = None
			
				if 'countryCode' in data['attributes']:
					#print(data['attributes']['countryCode'][0])
					countryCode = data['attributes']['countryCode'][0]
				else:
					countryCode = None
			
				if 'dNSHostName' in data['attributes']:
					#print(data['attributes']['dNSHostName'][0])
					dNSHostName = data['attributes']['dNSHostName'][0]
				else:
					dNSHostName = None
			
				if 'dSCorePropagationData' in data['attributes']:
					#print(data['attributes']['dSCorePropagationData'][0])
					dSCorePropagationData = data['attributes']['dSCorePropagationData'][0]
				else:
					dSCorePropagationData = None
			
				if 'distinguishedName' in data['attributes']:
					#print(data['attributes']['distinguishedName'][0])
					distinguishedName = data['attributes']['distinguishedName'][0]
				else:
					distinguishedName = None
			
				if 'instanceType' in data['attributes']:
					#print(data['attributes']['instanceType'][0])
					instanceType = data['attributes']['instanceType'][0]
				else:
					instanceType = None
			
				if 'isCriticalSystemObject' in data['attributes']:
					#print(data['attributes']['isCriticalSystemObject'][0])
					isCriticalSystemObject = data['attributes']['isCriticalSystemObject'][0]
				else:
					isCriticalSystemObject = None
			
				if 'lastLogoff' in data['attributes']:
					#print(data['attributes']['lastLogoff'][0])
					lastLogoff = data['attributes']['lastLogoff'][0]
				else:
					lastLogoff = None
			
				if 'lastLogon' in data['attributes']:
					#print(data['attributes']['lastLogon'][0])
					lastLogon = data['attributes']['lastLogon'][0]
				else:
					lastLogon = None
			
				if 'lastLogonTimestamp' in data['attributes']:
					#print(data['attributes']['lastLogonTimestamp'][0])
					lastLogonTimestamp = data['attributes']['lastLogonTimestamp'][0]
				else:
					lastLogonTimestamp = None
			
				if 'localPolicyFlags' in data['attributes']:
					#print(data['attributes']['localPolicyFlags'][0])
					localPolicyFlags = data['attributes']['localPolicyFlags'][0]
				else:
					localPolicyFlags = None
			
				if 'logonCount' in data['attributes']:
					#print(data['attributes']['logonCount'][0])
					logonCount = data['attributes']['logonCount'][0]
				else:
					logonCount = None
			
				if 'msDFSR-ComputerReferenceBL' in data['attributes']:
					#print(data['attributes']['msDFSR-ComputerReferenceBL'][0])
					msDFSR_ComputerReferenceBL = data['attributes']['msDFSR-ComputerReferenceBL'][0]
				else:
					msDFSR_ComputerReferenceBL = None
			
				if 'msDS-SupportedEncryptionTypes' in data['attributes']:
					#print(data['attributes']['msDS-SupportedEncryptionTypes'][0])
					msDS_SupportedEncryptionTypes = data['attributes']['msDS-SupportedEncryptionTypes'][0]
				else:
					msDS_SupportedEncryptionTypes = None
			
				if 'name' in data['attributes']:
					#print(data['attributes']['name'][0])
					name = data['attributes']['name'][0]
				else:
					name = None
			
				if 'objectCategory' in data['attributes']:
					#print(data['attributes']['objectCategory'][0])
					objectCategory = data['attributes']['objectCategory'][0]
				else:
					objectCategory = None
			
				if 'objectClass' in data['attributes']:
					#print(data['attributes']['objectClass'][0])
					objectClass = data['attributes']['objectClass'][0]
				else:
					objectClass = None
			
				if 'objectGUID' in data['attributes']:
					#print(data['attributes']['objectGUID'][0])
					objectGUID = data['attributes']['objectGUID'][0]
				else:
					objectGUID = None
			
				if 'objectSid' in data['attributes']:
					#print(data['attributes']['objectSid'][0])
					objectSid = data['attributes']['objectSid'][0]
				else:
					objectSid = None
			
				if 'operatingSystem' in data['attributes']:
					#print(data['attributes']['operatingSystem'][0])
					operatingSystem = data['attributes']['operatingSystem'][0]
				else:
					operatingSystem = None
			
				if 'operatingSystemVersion' in data['attributes']:
					#print(data['attributes']['operatingSystemVersion'][0])
					operatingSystemVersion = data['attributes']['operatingSystemVersion'][0]
				else:
					operatingSystemVersion = None
			
				if 'primaryGroupID' in data['attributes']:
					#print(data['attributes']['primaryGroupID'][0])
					primaryGroupID = data['attributes']['primaryGroupID'][0]
				else:
					primaryGroupID = None
			
				if 'pwdLastSet' in data['attributes']:
					#print(data['attributes']['pwdLastSet'][0])
					pwdLastSet = data['attributes']['pwdLastSet'][0]
				else:
					pwdLastSet = None
			
				if 'rIDSetReferences' in data['attributes']:
					#print(data['attributes']['rIDSetReferences'][0])
					rIDSetReferences = data['attributes']['rIDSetReferences'][0]
				else:
					rIDSetReferences = None
			
				if 'sAMAccountName' in data['attributes']:
					#print(data['attributes']['sAMAccountName'][0])
					sAMAccountName = data['attributes']['sAMAccountName'][0]
				else:
					sAMAccountName = None
			
				if 'sAMAccountType' in data['attributes']:
					#print(data['attributes']['sAMAccountType'][0])
					sAMAccountType = data['attributes']['sAMAccountType'][0]
				else:
					sAMAccountType = None
			
				if 'serverReferenceBL' in data['attributes']:
					#print(data['attributes']['serverReferenceBL'][0])
					serverReferenceBL = data['attributes']['serverReferenceBL'][0]
				else:
					serverReferenceBL = None
			
				if 'servicePrincipalName' in data['attributes']:
					#print(data['attributes']['servicePrincipalName'][0])
					servicePrincipalName = data['attributes']['servicePrincipalName'][0]
				else:
					servicePrincipalName = None
			
				if 'uSNChanged' in data['attributes']:
					#print(data['attributes']['uSNChanged'][0])
					uSNChanged = data['attributes']['uSNChanged'][0]
				else:
					uSNChanged = None
			
				if 'uSNCreated' in data['attributes']:
					#print(data['attributes']['uSNCreated'][0])
					uSNCreated = data['attributes']['uSNCreated'][0]
				else:
					uSNCreated = None
			
				if 'userAccountControl' in data['attributes']:
					#print(data['attributes']['userAccountControl'][0])
					userAccountControl = data['attributes']['userAccountControl'][0]
				else:
					userAccountControl = None
			
				if 'whenChanged' in data['attributes']:
					#print(data['attributes']['whenChanged'][0])
					whenChanged = data['attributes']['whenChanged'][0]
				else:
					whenChanged = None
			
				if 'whenCreated' in data['attributes']:
					#print(data['attributes']['whenCreated'][0])
					whenCreated = data['attributes']['whenCreated'][0]
				else:
					whenCreated = None
				
				attributes_.append((accountExpires, badPasswordTime, badPwdCount, cn, codePage, countryCode, dNSHostName,
				                dSCorePropagationData, distinguishedName, instanceType, isCriticalSystemObject, lastLogoff,
				                lastLogon, lastLogonTimestamp, localPolicyFlags, logonCount, msDFSR_ComputerReferenceBL,
				                msDS_SupportedEncryptionTypes, name, objectCategory, objectClass, objectGUID, objectSid,
				                operatingSystem, operatingSystemVersion, primaryGroupID, pwdLastSet, rIDSetReferences,
				                sAMAccountName, sAMAccountType, serverReferenceBL, servicePrincipalName, uSNChanged, uSNCreated,
				                userAccountControl, whenChanged, whenCreated))
				
				print(json.dumps(data, indent=4, sort_keys=True))				
				
				self.write_out(attributes_, '', attrib_type)
	
	def split_domain(self, domain):
		length = domain.split('.')
		if len(length) == 4:
			search_domain = 'dc={},dc={},dc={},dc={}'.format(length[0], length[1], length[2], length[3])
		elif len(length) == 3:
			search_domain = 'dc={},dc={},dc={}'.format(length[0], length[1], length[2])
		elif len(length) == 2:
			search_domain = 'dc={},dc={}'.format(length[0], length[1])
		else:
			self.logger.error('search_domain not valid: {}'.format(domain.split('.')))
			print('search_domain not valid: {}'.format(domain.split('.')))
			sys.exit()		
		return search_domain
	
	
	def search_ad(self, domains=[], users=[]):
		
		if not domains:
			print('no domain set')
			logger.error('no domain set')
			sys.exit()
		
		filters = ['(&(objectCategory=person)(objectClass=user)(name={}))',
		           '(&(objectCategory=person)(objectClass=user)(displayName={}))',
		           '(&(objectCategory=person)(objectClass=user)(cn={}))',
		           '(&(objectCategory=person)(objectClass=user)(description=*{}*))',
		           '(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))']	
		
		for domain in domains:
			search_domain = self.split_domain(domain)
			for user in users:
				for fil in filters:
					print(fil)
					self.ad.search(search_base=search_domain, search_scope='SUBTREE', search_filter=fil.format(user), attributes=['*'])
					print(obj.ad.entries)
	
	def all_machines(self, domains=[]):
		if not domains:
			print('no domain set')
			logger.error('no domain set')
			sys.exit()

		for domain in domains:
			search_domain = self.split_domain(domain)
			self.ad.search(search_base=search_domain, search_scope='SUBTREE', search_filter='(&(objectClass=Computer))', attributes=['*'])		
			self.attribute_parse(obj.ad.entries, 'computers')				
					
	def all_users(self, domains=[]):
		if not domains:
			print('no domain set')
			logger.error('no domain set')
			sys.exit()
			
		for domain in domains:
			search_domain = self.split_domain(domain)
			self.ad.search(search_base=search_domain, search_scope='SUBTREE', search_filter='(sAMAccountType=805306368)', attributes=['*'])
			self.attribute_parse(obj.ad.entries, 'users')
			
				
