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

from ansible.module_utils.basic import AnsibleModule

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
lookup: cyberarkpasswordvault
author: Jelle van de Haterd
version_added: "2.6"
short_description: get secrets from CyberArk Privileged Account Security
description:
  - Uses CyberArk Privileged Account Security REST API to fetch credentials

options:
  safe:
    description: the name of the safe to be queried.
    vars:
      - name: cyberark_safe
  passprops:
    description: Fetch properties assigned to the entry
    type: boolean
    default: False
    vars:
      - name: cyberark_passprops

  cyberark_connection:
    description: Default endpoint connection information
    vars:
      - name: cyberark_connection
    default: {}
    suboptions:
      url:
        description: url of cyberark PAS.
        env:
         - name: CYBERARK_URL
        vars:
          - name: url
        required: True
      username:
        description: cyberark authentication username.
        env:
          - name: CYBERARK_USERNAME
        vars:
          - name: username
        required: True
      password:
        description: cyberark authentication password.
        env:
          - name: CYBERARK_PASSWORD
        vars:
          - name: password
        required: True
      use_radius_authentication:
        description: use radius for cyberark authentication.
        env:
          - name: CYBERARK_USE_RADIUS_AUTHENTICATION
        default: false
        vars:
          - name: use_radius_authentication
      validate_certs:
        description: Flag to control SSL certificate validation
        type: boolean
        default: True
        vars:
          - name: validate_certs
      use_proxy:
        description: Flag to control if the lookup will observe HTTP proxy environment variables when present.
        type: boolean
        default: True
        vars:
          - name: use_proxy
"""

EXAMPLES = """
  - name: Fetch password matching keyword 'ansible'
    debug: msg={{lookup('cyberarkpasswordvault', 'ansible')}}
    vars:
      cyberark_connection:
        url: '{{ my_cyberark_url}}'
        username: "{{ my_username }}"
        password: "{{ my_password }}"
        validate_certs: true
        use_radius_authentication: false

  - name: Fetch password matching keyword 'ansible'
    debug: msg={{lookup('cyberarkpasswordvault', 'ansible', passprops=true)}}
    vars:
      cyberark_connection:
        url: '{{ my_cyberark_url}}'
        username: "{{ my_username }}"
        password: "{{ my_password }}"
        validate_certs: true
        use_radius_authentication: false
    register: passprops


"""

RETURN = """
  password:
    description:
      - The actual value stored
  passprops:
    description:
      - Properties assigned to the entry
    type: dictionary
"""

import os
import ssl
import json
import shelve
import socket
from os import getpid
from time import sleep, time
from ansible.parsing import vault
from ansible.errors import AnsibleError
from ansible.module_utils._text import to_bytes, to_text, to_native
from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError


try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

ANSIBLE_CYBERARK_URL = os.getenv('CYBERARK_URL', None)
ANSIBLE_CYBERARK_USERNAME = os.getenv('CYBERARK_USERNAME', None)
ANSIBLE_CYBERARK_PASSWORD = os.getenv('CYBERARK_PASSWORD', None)
ANSIBLE_CYBERARK_USE_RADIUS_AUTHENTICATION = os.getenv('CYBERARK_USE_RADIUS_AUTHENTICATION', False)
ANSIBLE_CYBERARK_REQUEST_TIMEOUT_SECONDS = os.getenv('CYBERARK_REQUEST_TIMEOUT_SECONDS', 600)


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


class CyberArkPasswordVaultConnector:

    def __init__(self, options, templar, cache_file=None):
        """Handles the authentication against the API and calls the appropriate API
        endpoints.
        """
        self._cache = None
        if cache_file is not None:
            self._cache = shelve.DbfilenameShelf(to_bytes(cache_file))
        self._session_token = None
        self._options = options
        self._templar = templar
        self.cyberark_connection = self._options.get('cyberark_connection', dict())
        self.cyberark_use_radius_authentication = ANSIBLE_CYBERARK_USE_RADIUS_AUTHENTICATION

        if 'cyberark_use_radius_authentication' in self.cyberark_connection:
            self.cyberark_use_radius_authentication = self.cyberark_connection['cyberark_use_radius_authentication']

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self._cache:
            self._cache.close()
        self.logoff()
        display.vvvv("CyberArk lookup: Logoff Succesfull")

    def request(self, api_endpoint, data=None, headers=None, method='GET', params=None):
        if self._session_token is None:
            self._session_token = self.logon()
            display.vvvv("CyberArk lookup: Logon succesfull")

        if headers is None:
            headers = {
                'Content-Type': 'application/json'
            }

        if method == 'POST' and data is None:
            headers.update({"Content-Length": 0})

        if self._session_token is not None:
            headers['Authorization'] = self._session_token

        url = '{base_url}/PasswordVault/{api_endpoint}'.format(
            base_url=self.cyberark_connection.get('url', ANSIBLE_CYBERARK_URL),
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
                use_proxy=self.cyberark_connection.get('use_proxy', True),
                timeout=60
            )
        except HTTPError as e:
            if e.code == 500:
                if e.reason.startswith('ITATS127E'):  # account locked, open unapproved request
                    raise PWVAccountLocked("Account locked: %s" % e.reason)
                if e.reason.startswith('ITATS534E'):  # no request for this account
                    raise PWVAccountNoRequest("No request: %s " % e.reason)

            raise AnsibleError("Received HTTP error for %s : %s" % (url, to_native(e)))
        except URLError as e:
            raise AnsibleError("Failed lookup url for %s : %s" % (url, to_native(e)))
        except SSLValidationError as e:
            raise AnsibleError("Error validating the server's certificate for %s: %s" % (url, to_native(e)))
        except ConnectionError as e:
            raise AnsibleError("Error connecting to %s: %s" % (url, to_native(e)))
        except socket.timeout as e:
            raise AnsibleError("Error connecting to %s: %s" % (url, to_native(e)))
        except ssl.SSLError as e:
            raise AnsibleError("Error connecting to %s: %s" % (url, to_native(e)))
        else:
            display.vvvv("CyberArk lookup: received response")
            return response

    def logon(self):
        self._session_token = 'init'

        username = self._templar.template(self.cyberark_connection.get('username', ANSIBLE_CYBERARK_USERNAME), fail_on_undefined=True)
        password = self._templar.template(self.cyberark_connection.get('password', ANSIBLE_CYBERARK_PASSWORD), fail_on_undefined=True)

        payload = json.dumps({
            "username": username,
            "password": password,
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

        return json.loads(response.read())['CyberArkLogonResult']

    def logoff(self):

        if self._session_token is not None:
            self.request(
                api_endpoint='WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff',
                method='POST'
            )

    def get_accounts(self, keywords, safe=None):
        """This method enables users to retrieve the password of an
        existing account that is identified by its Account ID.
        """

        if not safe:
            safe = self._templar.template(self._options.get('safe'), fail_on_undefined=True)

        if self._cache and to_bytes(keywords) in self._cache:
            display.vvvv('Cache retrieval for keywords: %s, safe: %s' % (keywords, safe))
            result = self._cache.get(to_bytes(keywords))
        else:
            params = {'Keywords': keywords}
            if safe:
                params['Safe'] = safe

            response = self.request(
                api_endpoint='WebServices/PIMServices.svc/Accounts',
                params=params
            )
            result = json.loads(response.read())

            if result["Count"] == 0:
                raise AnsibleError("Search result contains no accounts")

            if self._cache is not None:
                display.vvvv('Write result to cache with keywords: %s' % keywords)
                self._cache[to_bytes(keywords)] = result
        return result

    def get_account(self, keywords, safe=None):
        account_details = self.get_accounts(keywords, safe=safe)

        if account_details["Count"] != 1:
            raise AnsibleError("Search result contains none or more than 1 account")

        return account_details['accounts'][0]['AccountID'], account_details['accounts'][0]

    def get_password(self, account_id):
        """This method enables users to retrieve the password of an
        existing account that is identified by its Account ID.
        """

        api_endpoint = 'WebServices/PIMServices.svc/Accounts/{account_id}/Credentials'.format(
            account_id=account_id
        )

        v = vault.VaultLib(
            [(to_bytes(account_id), vault.VaultSecret(to_bytes(self.cyberark_connection.get('password', ANSIBLE_CYBERARK_PASSWORD))))]
        )

        if self._cache and to_bytes(account_id) in self._cache:
            result = v.decrypt(self._cache.get(to_bytes(account_id)))
        else:
            try:
                response = self.request(api_endpoint=api_endpoint)
                result = to_text(response.read())
                if self._cache:
                    self._cache[to_bytes(account_id)] = v.encrypt(result)
            except HTTPError as e:
                return

        return result

    def get_password_for_account(self, keywords, safe=None):

        account_id, account_details = self.get_account(keywords, safe=safe)

        display.vv("account_details: %s " % account_details)

        result = dict()

        result.update({
            prop['Key'].lower(): prop['Value'] for prop in account_details['Properties']
        })
        result.update({
            'password': self.get_password(account_id)
        })

        return result if self._options.get('passprops') else result['password']

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
            request_by_name = list(filter(lambda x: name in x['AccountDetails']['Properties']['Name'] and x['AccountDetails']['Properties']['Safe'] == safe, requests['MyRequests']))
        else:
            request_by_name = list(filter(lambda x: name in x['AccountDetails']['Properties']['Name'], requests['MyRequests']))

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
        timeout = ANSIBLE_CYBERARK_REQUEST_TIMEOUT_SECONDS
        time_start = time()
        while time() < time_start + timeout:
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

    def create_request(self, account_id, reason, period):
        display.v("Creating request for: %s (%s) " % (account_id, reason))
        now = int(time())

        payload = json.dumps({
            "AccountID": account_id,
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

    def request_password(self, keyword, wait, reason, period, safe=None):

        account_id, account_details = self.get_account(keyword, safe)

        try:
            request = self.get_request(keyword, safe)
            if not request:
                self.create_request(account_id, reason, period)
                request = self.get_request(keyword, safe)
        except PWVRequestInvalid as e:
            raise AnsibleError("could create request: %s" % e)

        if not request:
            raise AnsibleError("passwordvault request could not be found or created. Reason unknown")

        if wait:
            success, status, reason = self.wait_for_request_final_state(request['RequestID'])
            if not success:
                raise AnsibleError("passwordvault request failed: %s - %s" % (status, reason))

        try:
            password = self.get_password(account_details['AccountID'])
            return {'keyword': keyword, 'password': password, 'safe': safe}
        except PWVAccountLocked as e:
            return {'failure': u"Account Locked: %s" % to_text(e)}
        except PWVAccountNoRequest as e:
            return {'failure': u"No Request: %s" % to_text(e)}
