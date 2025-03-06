#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version of the Apache Software License.
# See the accompanying LICENSE file for more information.
#
# Description:
#   This module queries a target domain for delegation relationships by searching for
#   unconstrained, constrained, and resource-based constrained delegations.
#   Additionally, it enumerates privileged accounts (Domain Admins, Administrators, Protected Users)
#   and, using the --admin-group flag, allows specifying one or more additional admin groups.
#   For each additional admin group, the script correlates its members and checks whether they have:
#       - Membership in "Protected Users"
#       - The flag "account is sensitive and cannot be delegated" (UF_NOT_DELEGATED)
#

from __future__ import division, print_function

import argparse
import logging
import sys

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
# Constant for "account is sensitive and cannot be delegated"
UF_NOT_DELEGATED = 0x100000

from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1
from impacket.ldap import ldaptypes
from impacket.smbconnection import SMBConnection, SessionError


def checkIfSPNExists(ldapConnection, sAMAccountName, rights):
    """
    Check if the specified SPN exists in the LDAP directory.
    """
    spnExists = "-"
    if rights == "N/A":
        query = "(servicePrincipalName=HOST/%s)" % sAMAccountName.rstrip("$")
    else:
        query = "(servicePrincipalName=%s)" % rights

    respSpnExists = ldapConnection.search(
        searchFilter=query,
        attributes=["servicePrincipalName", "distinguishedName"],
        sizeLimit=1
    )
    results = [item for item in respSpnExists if isinstance(item, ldapasn1.SearchResultEntry)]
    if results:
        spnExists = "Yes"
    else:
        spnExists = "No"
    return spnExists


class FindDelegation:
    @staticmethod
    def printTable(items, header):
        # Determine the maximum width for each column
        colLen = []
        for i, col in enumerate(header):
            # Consider both header and every row
            maxLen = max([len(row[i]) for row in items] + [len(col)])
            colLen.append(maxLen)
        # Build a format string with two spaces as a separator
        outputFormat = '  '.join(['{{{0}:{1}s}}'.format(i, colLen[i]) for i in range(len(colLen))])
        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * colLen[i] for i in range(len(colLen))]))
        # Print each row
        for row in items:
            print(outputFormat.format(*row))

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__target = None
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        # New flag: list of additional target admin groups (DN or CN)
        self.__adminGroupsTarget = cmdLineOptions.admin_group if cmdLineOptions.admin_group is not None else []
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Build the baseDN
        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for part in domainParts:
            self.baseDN += 'dc=%s,' % part
        self.baseDN = self.baseDN[:-1]
        if user_domain != self.__targetDomain and (self.__kdcIP or self.__kdcHost):
            logging.warning('KDC IP address and hostname will be ignored because of cross-domain targeting.')
            self.__kdcIP = None
            self.__kdcHost = None

    def getMachineName(self, target):
        try:
            s = SMBConnection(target, target)
            s.login('', '')
        except OSError as e:
            if 'timed out' in str(e):
                raise Exception('The connection timed out. Probably port 445/TCP is closed. Try specifying the '
                                'corresponding NetBIOS name or FQDN using the -dc-host option.')
            else:
                raise
        except SessionError as e:
            if 'STATUS_NOT_SUPPORTED' in str(e):
                raise Exception('The SMB request is not supported. Probably NTLM is disabled. Try specifying the '
                                'corresponding NetBIOS name or FQDN using the -dc-host option.')
            else:
                raise
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymously logging into %s' % target)
        else:
            s.logoff()
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    def run(self):
        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None and self.__targetDomain == self.__domain:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__targetDomain

            if self.__doKerberos:
                logging.info('Getting machine hostname')
                self.__target = self.getMachineName(self.__target)

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcIP)
            if not self.__doKerberos:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain,
                                             self.__lmhash, self.__nthash, self.__aesKey, kdcHost=self.__kdcIP)
        except ldap.LDAPSessionError as e:
            if 'strongerAuthRequired' in str(e):
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcIP)
                if not self.__doKerberos:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain,
                                                 self.__lmhash, self.__nthash, self.__aesKey, kdcHost=self.__kdcIP)
            else:
                if self.__kdcIP is not None and self.__kdcHost is not None:
                    logging.critical("If the credentials are valid, ensure that the KDC hostname and IP address match exactly")
                raise

        # --- Search for Delegation Relationships ---
        searchFilter = ("(&(|(UserAccountControl:1.2.840.113556.1.4.803:=16777216)"
                        "(UserAccountControl:1.2.840.113556.1.4.803:=524288)"
                        "(msDS-AllowedToDelegateTo=*)"
                        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
                        "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"
                        "(!(UserAccountControl:1.2.840.113556.1.4.803:=8192)))")
        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['sAMAccountName', 'pwdLastSet',
                                                     'userAccountControl', 'objectCategory',
                                                     'msDS-AllowedToActOnBehalfOfOtherIdentity',
                                                     'msDS-AllowedToDelegateTo'],
                                         sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if 'sizeLimitExceeded' in e.getErrorString():
                logging.debug('sizeLimitExceeded exception caught, processing received data')
                resp = e.getAnswers()
            else:
                raise

        answers = []
        logging.debug('Total delegation records returned: %d' % len(resp))
        
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            mustCommit = False
            sAMAccountName = ''
            userAccountControl = 0
            delegation = ''
            objectType = ''
            rightsTo = []
            protocolTransition = 0

            for attribute in item['attributes']:
                if str(attribute['type']) == 'sAMAccountName':
                    sAMAccountName = str(attribute['vals'][0])
                    mustCommit = True
                elif str(attribute['type']) == 'userAccountControl':
                    userAccountControl = str(attribute['vals'][0])
                    if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                        delegation = 'Unconstrained'
                        rightsTo.append("N/A")
                    elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                        delegation = 'Constrained w/ Protocol Transition'
                        protocolTransition = 1
                elif str(attribute['type']) == 'objectCategory':
                    objectType = str(attribute['vals'][0]).split('=')[1].split(',')[0]
                elif str(attribute['type']) == 'msDS-AllowedToDelegateTo':
                    if protocolTransition == 0:
                        delegation = 'Constrained'
                    for delegRights in attribute['vals']:
                        rightsTo.append(str(delegRights))
                
                # RBCD: Handle msDS-AllowedToActOnBehalfOfOtherIdentity
                if str(attribute['type']) == 'msDS-AllowedToActOnBehalfOfOtherIdentity':
                    rbcdRights = []
                    rbcdObjType = []
                    adminSearchFilter = '(&(|'
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(attribute['vals'][0]))
                    for ace in sd['Dacl'].aces:
                        adminSearchFilter += "(objectSid=" + ace['Ace']['Sid'].formatCanonical() + ")"
                    adminSearchFilter += ")(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"
                    delegUserResp = ldapConnection.search(searchFilter=adminSearchFilter,
                                                          attributes=['sAMAccountName', 'objectCategory'],
                                                          sizeLimit=999)
                    for item2 in delegUserResp:
                        if not isinstance(item2, ldapasn1.SearchResultEntry):
                            continue
                        rbcdRights.append(str(item2['attributes'][0]['vals'][0]))
                        rbcdObjType.append(str(item2['attributes'][1]['vals'][0]).split('=')[1].split(',')[0])
                        
                    if mustCommit:
                        if int(userAccountControl) & UF_ACCOUNTDISABLE:
                            logging.debug('Bypassing disabled account %s' % sAMAccountName)
                        else:
                            for rights, objType in zip(rbcdRights, rbcdObjType):
                                spnExists = checkIfSPNExists(ldapConnection, sAMAccountName, rights)
                                answers.append([sAMAccountName, objType, 'Resource-Based Constrained', rights, spnExists])
            
            if delegation in ['Unconstrained', 'Constrained', 'Constrained w/ Protocol Transition']:
                if mustCommit:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        logging.debug('Bypassing disabled account %s' % sAMAccountName)
                    else:
                        for rights in rightsTo:
                            spnExists = checkIfSPNExists(ldapConnection, sAMAccountName, rights)
                            answers.append([sAMAccountName, objectType, delegation, rights, spnExists])

        if answers:
            print("\nDelegation Relationships:")
            # Print table without the "Sensitive" column
            self.printTable(answers, header=["AccountName", "AccountType", "DelegationType", "DelegationRightsTo", "SPN Exists"])
            print('\n')
        else:
            print("No delegation entries found!\n")

        # --- Enumerate Privileged Accounts (Domain Admins, Administrators, Protected Users) ---
        admin_filter = ("(&(objectCategory=person)(objectClass=user)"
                        "(|(memberOf=CN=Domain Admins,CN=Users,{0})"
                        "(memberOf=CN=Administrators,CN=Builtin,{0})))").format(self.baseDN)
        try:
            admin_resp = ldapConnection.search(searchFilter=admin_filter,
                                               attributes=['sAMAccountName', 'userAccountControl', 'memberOf'],
                                               sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if 'sizeLimitExceeded' in e.getErrorString():
                logging.debug('sizeLimitExceeded exception caught while searching admin accounts, processing received data')
                admin_resp = e.getAnswers()
            else:
                raise

        admins = []
        for item in admin_resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            sAMAccountName = ''
            userAccountControl = 0
            groups = []
            protectedFlag = "No"
            for attribute in item['attributes']:
                if str(attribute['type']) == 'sAMAccountName':
                    sAMAccountName = str(attribute['vals'][0])
                elif str(attribute['type']) == 'userAccountControl':
                    userAccountControl = int(attribute['vals'][0])
                elif str(attribute['type']) == 'memberOf':
                    for val in attribute['vals']:
                        group = str(val)
                        if "CN=Domain Admins," in group:
                            groups.append("Domain Admins")
                        if "CN=Administrators," in group:
                            groups.append("Administrators")
                        if "CN=Protected Users," in group:
                            groups.append("Protected Users")
            groups = list(set(groups))
            groupStr = ", ".join(groups) if groups else ""
            sensitiveFlag = "Yes" if userAccountControl & UF_NOT_DELEGATED else "No"
            if "Protected Users" in groups:
                protectedFlag = "Yes"
            admins.append([sAMAccountName, groupStr, sensitiveFlag, protectedFlag])
        
        if admins:
            print("Privileged Accounts:")
            self.printTable(admins, header=["AccountName", "Groups", "Sensitive", "Protected"])
            print('\n')
        else:
            print("No privileged accounts found!\n")

        # --- Automatically Enumerate Administrative Groups (based on SID) ---
        adminGroups = []
        groupFilter = "(&(objectCategory=group))"
        try:
            groupsResp = ldapConnection.search(searchFilter=groupFilter,
                                               attributes=['cn', 'objectSid'],
                                               sizeLimit=0)
        except ldap.LDAPSearchError as e:
            logging.debug('sizeLimitExceeded exception caught while searching groups, processing received data')
            groupsResp = e.getAnswers()
        
        for item in groupsResp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            groupName = ''
            groupSidStr = ''
            for attr in item['attributes']:
                if str(attr['type']) == 'cn':
                    groupName = str(attr['vals'][0])
                elif str(attr['type']) == 'objectSid':
                    try:
                        sidObj = ldaptypes.SID(data=bytes(attr['vals'][0]))
                        groupSidStr = sidObj.formatCanonical()
                    except Exception:
                        groupSidStr = ""
            if groupSidStr:
                rid = groupSidStr.split('-')[-1]
                # Well-known RIDs for administrative groups: 512, 518, 519, 544
                if rid in ['512', '518', '519', '544']:
                    adminGroups.append([groupName, groupSidStr])
        
        if adminGroups:
            print("Admin Groups (enumerated automatically based on well-known RID):")
            self.printTable(adminGroups, header=["GroupName", "ObjectSID"])
            print('\n')

        # --- Correlate Additional Admin Group Members (specified via --admin-group) ---
        if self.__adminGroupsTarget:
            additional_admins = []
            for groupInput in self.__adminGroupsTarget:
                # If the provided group does not contain a comma, assume it's a CN and build the DN under CN=Users
                if ',' not in groupInput:
                    group_dn = "CN=%s,CN=Users,%s" % (groupInput, self.baseDN)
                else:
                    group_dn = groupInput
                group_filter = "(&(objectCategory=person)(objectClass=user)(memberOf={}))".format(group_dn)
                try:
                    group_resp = ldapConnection.search(searchFilter=group_filter,
                                                       attributes=['sAMAccountName', 'userAccountControl', 'memberOf'],
                                                       sizeLimit=999)
                except ldap.LDAPSearchError as e:
                    if 'sizeLimitExceeded' in e.getErrorString():
                        logging.debug("sizeLimitExceeded exception caught while searching for members of %s, processing data" % group_dn)
                        group_resp = e.getAnswers()
                    else:
                        raise

                for item in group_resp:
                    if not isinstance(item, ldapasn1.SearchResultEntry):
                        continue
                    sAMAccountName = ''
                    userAccountControl = 0
                    groups_list = []
                    for attribute in item['attributes']:
                        if str(attribute['type']) == 'sAMAccountName':
                            sAMAccountName = str(attribute['vals'][0])
                        elif str(attribute['type']) == 'userAccountControl':
                            userAccountControl = int(attribute['vals'][0])
                        elif str(attribute['type']) == 'memberOf':
                            for val in attribute['vals']:
                                groups_list.append(str(val))
                    groups_list = list(set(groups_list))
                    sensitiveFlag = "Yes" if userAccountControl & UF_NOT_DELEGATED else "No"
                    protectedFlag = "Yes" if any("CN=Protected Users," in g for g in groups_list) else "No"
                    additional_admins.append([groupInput, sAMAccountName, sensitiveFlag, protectedFlag])
            if additional_admins:
                print("Additional Admin Group Members (targeted via --admin-group):")
                self.printTable(additional_admins, header=["Target Group", "AccountName", "Sensitive", "Protected"])
                print('\n')
            else:
                print("No members found for specified additional admin groups!\n")


# Command-line argument processing.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
                                     description="Queries target domain for delegation relationships")
    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    parser.add_argument('-target-domain', action='store',
                        help='Domain to query/request if different than the user domain. '
                             'Allows retrieving delegation info across trusts.')
    parser.add_argument('-ts', action='store_true', help='Add timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH",
                       help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help="Don't ask for password (useful for -k)")
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on '
                            'target parameters. If valid credentials cannot be found, it will use those specified on '
                            'the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key",
                       help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address',
                       help='IP Address of the domain controller. If omitted, uses the domain part (FQDN) specified in '
                            'the target parameter. Ignored if -target-domain is specified.')
    group.add_argument('-dc-host', action='store', metavar='hostname',
                       help='Hostname of the domain controller to use. If omitted, the domain part (FQDN) specified in the '
                            'account parameter will be used')

    # New flag for specifying additional admin groups with example usage.
    group = parser.add_argument_group('targeting')
    group.add_argument('-admin-group', action='append',
                       help='Target additional admin groups (DN or CN). Example: --admin-group MyAdminGroup or '
                            '--admin-group "CN=CustomAdminGroup,OU=Admins,DC=domain,DC=com"')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.ts)

    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    userDomain, username, password = parse_credentials(options.target)

    if userDomain == '':
        logging.critical('userDomain must be specified!')
        sys.exit(1)

    if options.target_domain:
        targetDomain = options.target_domain
    else:
        targetDomain = userDomain

    if password == '' and username != '' and options.hashes is None and not options.no_pass and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    try:
        executer = FindDelegation(username, password, userDomain, targetDomain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
