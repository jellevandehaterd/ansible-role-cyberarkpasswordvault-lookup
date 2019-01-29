# (c) 2018, Ansible Project
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
from os import getpid
from time import sleep, time

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_text, to_native
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError

from ansible.plugins.action import ActionBase

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


class PWVAccountLocked(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class PWVAccountNoRequest(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class PWVRequestInvalid(Exception):
    def __init__(self, requestID, status, reason):
        self.requestID = requestID
        self.status = status
        self.reason = reason

    def __str__(self):
        return "%s: %s" % (repr(self.status), repr(self.reason))


def hasFailed(result, reason):
    result['failed'] = True
    result['msg'] = reason
    return result

class CyberArkPasswordVaultConnector:

    def __init__(self, options):
        """Handles the authentication against the API and calls the appropriate API
        endpoints.
        """
        self._session_token = None
        self._options = options
        self.cyberark_connection = self._options.get('cyberark_connection', dict())
        self.cyberark_use_radius_authentication = False

        if self.cyberark_connection.get('cyberark_use_radius_authentication', False):
            self.cyberark_use_radius_authentication = True

    def __enter__(self):
        if not self._session_token:
            self.logon()
            display.vvvv("CyberArk lookup: Logon succesfull")
        return self

    def __exit__(self, *args):
        self.logoff()
        display.vvvv("CyberArk lookup: Logoff Succesfull")

    def request(self, api_endpoint, data=None, headers=None, method='GET', params=None):

        if headers is None:
            headers = {
                'Content-Type': 'application/json'
            }

        if method == 'POST' and data is None:
            headers.update({"Content-Length": 0})
        elif method == 'POST' and data is not None:
            headers.update({"Content-Length": len(data)})

        if self._session_token is not None:
            headers['Authorization'] = self._session_token

        url = '{base_url}/PasswordVault/{api_endpoint}'.format(
            base_url=self.cyberark_connection.get('url'),
            api_endpoint=api_endpoint
        )

        if params:
            params = urlencode(params)
            url = '{url}?{querystring}'.format(url=url, querystring=params)

        display.vvvv("CyberArk lookup: connecting to API endpoint %s" % url)
        try:
            response = open_url(
                url=url,
                data=data,
                headers=headers,
                method=method,
                validate_certs=self.cyberark_connection.get('validate_certs', True),
                use_proxy=self.cyberark_connection.get('use_proxy', True)
            )
        except HTTPError as e:
            if e.code == 500:
                if e.reason.startswith('ITATS127E'): # account locked, open unapproved request
                    raise PWVAccountLocked("Account locked: %s" % e.reason)
                if e.reason.startswith('ITATS534E'): # no request for this account
                    raise PWVAccountNoRequest("No request: %s "%  e.reason)

            raise AnsibleError("Received HTTP error for %s : %s" % (url, to_native(e)))
        except URLError as e:
            raise AnsibleError("Failed lookup url for %s : %s" % (url, to_native(e)))
        except SSLValidationError as e:
            raise AnsibleError("Error validating the server's certificate for %s: %s" % (url, to_native(e)))
        except ConnectionError as e:
            raise AnsibleError("Error connecting to %s: %s" % (url, to_native(e)))
        else:
            display.vvvv("CyberArk lookup: received response")
            return response

    def logon(self):

        payload = json.dumps({
            "username": self.cyberark_connection.get('username'),
            "password": self.cyberark_connection.get('password'),
            "useRadiusAuthentication": "{radius}".format(radius=str(self.cyberark_use_radius_authentication).lower()),
            # This is intended to ensure the following:
            # - The number is between 1 and 100
            # - Every ansible fork gets a different number to ensure concurrency.
            "connectionNumber": "%s" % ((getpid() % 99) + 1)
        }, indent=2, sort_keys=False)

        response = self.request(
            api_endpoint='WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logon',
            data=payload,
            method='POST'
        )

        self._session_token = json.loads(response.read())['CyberArkLogonResult']

    def logoff(self):

        if self._session_token is not None:
            self.request(
                api_endpoint='WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff',
                method='POST'
            )

    def get_account_details(self, keywords, safe=None ):
        """This method enables users to retrieve the password of an
        existing account that is identified by its Account ID.
        """
        display.vvvv('safe: %s, keywords: %s' % (safe, keywords))

        params = {'Keywords': keywords}
        if safe:
            params['Safe'] = safe

        response = self.request(
            api_endpoint='WebServices/PIMServices.svc/Accounts',
            params=params
        )

        return json.loads(response.read())

    def get_single_account(self, search, safe=None):
        account_details = self.get_account_details(search, safe=safe)

        if account_details["Count"] == 0:
            raise AnsibleError("Search result contains no accounts")
        elif account_details["Count"] > 1:
            list_of_nodes = []
            for account in account_details["accounts"]:
                list_of_nodes.append(account["Properties"]["Name"])

            raise AnsibleError("Search result contains more than 1 account: %s" % ", ".join(list_of_nodes))

        return account_details['accounts'][0]['AccountID'], account_details['accounts'][0]


    def get_password_value(self, account_id):
        """This method enables users to retrieve the password of an
        existing account that is identified by its Account ID.
        """

        api_endpoint = 'WebServices/PIMServices.svc/Accounts/{account_id}/Credentials'.format(
            account_id=account_id
        )

        try:
            response = self.request(api_endpoint=api_endpoint)
        except HTTPError as e:
            return

        return to_text(response.read())

    def get_my_requests(self):

        api_endpoint = 'API/MyRequests?onlywaiting=false&expired=false'

        try:
            response = self.request(api_endpoint=api_endpoint)
        except HTTPError as e:
            return

        return json.loads(response.read())

    def get_request(self, name, safe=None):

        requests = self.get_my_requests()

        if safe:
            request_by_name = list(filter(lambda x: x['AccountDetails']['Properties']['Name'] == name and x['AccountDetails']['Properties']['Safe'] == safe, requests['MyRequests']))
        else:
            request_by_name = list(filter(lambda x: x['AccountDetails']['Properties']['Name'] == name, requests['MyRequests']))

        if not len(request_by_name):
            return None
        elif len(request_by_name) == 1:
            return request_by_name[0]

        raise AnsibleError("Unexpectedly multiple requests found for '%s' in safe '%s'. Try specifying a safe or more specific searches")

    def get_request_by_id(self, request_id):
        api_endpoint = 'API/MyRequests/%s' % request_id

        try:
            response = self.request(api_endpoint=api_endpoint)
        except HTTPError as e:
            return

        return json.loads(response.read())


    def wait_for_request_final_state(self, request_id):

        while True:
            req = self.get_request_by_id(request_id)

            display.display("[%s] status: %s" % (req["AccountDetails"]["Properties"]["Name"], req["StatusTitle"]))
            if req['Status'] == 1:
                # still waiting
                pass
            elif req['Status'] == 2:
                # done
                # display.display("[%s] status: %s" % (req["AccountDetails"]["Properties"]["Name"], req["StatusTitle"]))
                break
            elif req['Status'] == 7:
                return False, req["StatusTitle"], req['InvalidRequestReason']
            else:
                return False, req["StatusTitle"], req['InvalidRequestReason']

            sleep(30)

        return True, None, None

    def create_request(self, accountID, reason, period):
        display.v("Creating request for: %s (%s) "% (accountID, reason))
        now  = int(time())

        payload = json.dumps({
            "AccountID": accountID,
            "Reason": reason,
            "fromDate": now,
            "toDate": now+period,
            "hasTimeframe": True,
            "MultipleAccessRequired": True,
        }, indent=2, sort_keys=False)

        display.v(payload)

        response = self.request(
            api_endpoint='API/MyRequests',
            data=payload,
            method='POST'
        )

        # if response.status != 201:
        #     raise PWVRequestInvalid(0, "unexpected return code", "%s instead of 201" % response.status_code)

        response = json.loads(response.read())

        if response['Status'] == 7:
            raise PWVRequestInvalid(response['RequestID'], response['StatusTitle'], response['StatusRequestReason'])

        return response['RequestID']





class ActionModule(ActionBase):

    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        '''
        Action plugin handler for creating password vault requests.
        '''

        self._supports_check_mode = True
        self._supports_async = False

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        url = self._task.args.get('url', 'https://pwv.europe.intranet')

        username = self._task.args.get('username')
        password = self._task.args.get('password')
        use_radius_authentication = boolean(self._task.args.get('use_radius_authentication', True), strict=False)
        validate_certs = boolean(self._task.args.get('validate_certs', True), strict=False)
        use_proxy = boolean(self._task.args.get('use_proxy', True), strict=False)

        keywords  = self._task.args.get('keywords', [])
        safe = self._task.args.get('safe')
        reason = self._task.args.get('reason')
        wait = boolean(self._task.args.get('wait', True), strict=False)

        if not username:
            return hasFailed(result, "username parameter should contain the loginname for the passwordvault")

        if not password:
            return hasFailed(result, "password parameter should contain the password for the passwordvault")

        if isinstance(keywords, str): #convert a single keyword to a list with 1 entry
            keywords = [ keywords ]

        if len(keywords) == 0:
            return hasFailed(result, "keywords parameter should contain a single keyword or a list of keywords.")

        try:
            period = int(self._task.args.get('period'))
        except ValueError as e:
            result['failed'] = True
            result['msg'] = u"non-integer value given for request period: %s" % to_text(e)
            return result

        options = {
          'cyberark_connection': {
            'url': url,
            'username': username,
            'password': password,
            'use_radius_authentication': use_radius_authentication,
            'validate_certs': validate_certs,
            'use_proxy': use_proxy
            },
        }

        with CyberArkPasswordVaultConnector(options) as vault:
            result['results'] =[]
            for name in keywords:
                single_result = self.request_password(name, safe, vault, wait, reason, period)

                if 'failure' in single_result:
                    result['failed'] = True
                    result['msg'] = single_result['failure']
                    return result

                result['results'].append(single_result)

        return result



    def request_password(self, name, safe, vault, wait, reason, period):
        result = {}

        accountID, account_details = vault.get_single_account(
            safe=self._templar.template(safe, fail_on_undefined=True),
            search=self._templar.template(name, fail_on_undefined=True),
        )

        display.v("account_details: %s " % account_details)

        try:
            request = vault.get_request(name, safe)
            if not request:
                vault.create_request(accountID, reason, period)
                request = vault.get_request(name, safe)
        except PWVRequestInvalid as e:
            raise AnsibleError("could create request: %s" % e )

        if not request:
            raise AnsibleError("passwordvault request could not be found or created. Reason unknown")

        if not wait:
            return {}

        success, status, reason = vault.wait_for_request_final_state(request['RequestID'])
        if not success:
            raise AnsibleError("passwordvault request failed: %s - %s" % (status, reason))

        try:
            password = vault.get_password_value(account_details['AccountID'])
            return {'keyword': name, 'password': password, 'safe': safe}
        except PWVAccountLocked as e:
            return {'failure': u"Account Locked: %s" % to_text(e) }
        except PWVAccountNoRequest as e:
            return {'failure': u"No Request: %s" % to_text(e) }
