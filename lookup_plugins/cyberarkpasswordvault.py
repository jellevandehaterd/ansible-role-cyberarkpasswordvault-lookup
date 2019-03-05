# (c) 2018, Jelle van de Haterd <j.vandehaterd@developers.nl>
# (c) 2018 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
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
import json
from os import getpid
from datetime import datetime
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.module_utils._text import to_text, to_native
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


class CyberArkPasswordVaultConnector:

    def __init__(self, options, templar):
        """Handles the authentication against the API and calls the appropriate API
        endpoints.
        """
        self._session_token = None
        self._options = options
        self._templar = templar
        self.cyberark_connection = self._options.get('cyberark_connection', dict())
        self.cyberark_use_radius_authentication = False

        if self.cyberark_connection.get('cyberark_use_radius_authentication', ANSIBLE_CYBERARK_USE_RADIUS_AUTHENTICATION):
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
                use_proxy=self.cyberark_connection.get('use_proxy', True)
            )
        except HTTPError as e:
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

        # make sure we render any jinja templates
        username=self._templar.template(self.cyberark_connection.get('username', ANSIBLE_CYBERARK_USERNAME), fail_on_undefined=True)
        password=self._templar.template(self.cyberark_connection.get('password', ANSIBLE_CYBERARK_PASSWORD), fail_on_undefined=True)

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

        self._session_token = json.loads(response.read())['CyberArkLogonResult']

    def logoff(self):

        if self._session_token is not None:
            self.request(
                api_endpoint='WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff',
                method='POST'
            )

    def get_account_details(self, safe, keywords=None):
        """This method enables users to retrieve the password of an
        existing account that is identified by its Account ID.
        """
        display.vvvv('safe: %s, keywords: %s' % (safe, keywords))
        response = self.request(
            api_endpoint='WebServices/PIMServices.svc/Accounts',
            params={'Safe': safe, 'Keywords': keywords}
        )

        return json.loads(response.read())

    def get_password_value(self, account_id):
        """This method enables users to retrieve the password of an
        existing account that is identified by its Account ID.
        """

        api_endpoint = 'WebServices/PIMServices.svc/Accounts/{account_id}/Credentials'.format(
            account_id=account_id
        )

        response = self.request(
            api_endpoint=api_endpoint
        )

        return to_text(response.read())

    #TODO add api V10 support
    def get_password_value_v10(self):
        """This method enables users to retrieve the password or SSH key of an existing account that is identified
        by its Account ID. It enables users to specify a reason and ticket ID, if required.
        This method can be used from v10 and replaces the Get Account Value method."""
        payload = {
            "Reason": "Automatically retrieved password by Ansible on {timestamp}".format(timestamp=datetime.now()),
            "TicketingSystemName": "ServiceNow",
            "TicketId": "INC123456",
            "Version": "1",
            "ActionType": "Connect",
            "IsUse": "false",
            "Machine": "client.cyberark.local"
        }
        api_endpoint = 'API/Accounts/{app_id}/Password/Retrieve'.format(
            app_id=self.cyberark_app_id
        )

        response = self.request(api_endpoint, data=payload, method='POST')

        return json.loads(response.read())


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):

        if not isinstance(terms, list):
            terms = [terms]
        elif isinstance(terms, list) and len(terms) == 1:
            if isinstance(terms[0], list):
                terms = terms[0]

        ret = []

        self.set_options(var_options=variables, direct=kwargs)

        with CyberArkPasswordVaultConnector(self._options, self._templar) as vault:

            for term in terms:
                account_details = vault.get_account_details(
                    safe=self._templar.template(self.get_option('safe'), fail_on_undefined=True),
                    keywords=term,
                )

                if account_details["Count"] == 0:
                    raise AnsibleError("Search result contains no accounts")
                elif account_details["Count"] > 1:
                    list_of_nodes = []
                    for account in account_details["accounts"]:
                        list_of_nodes.append(account["Properties"]["Name"])

                    raise AnsibleError("Search result contains more than 1 account: %s" % ", ".join(list_of_nodes))

                result = dict()
                password = vault.get_password_value(account_details["accounts"][0]["AccountID"])

                if self.get_option('passprops'):
                    result.update({
                        prop['Key'].lower(): prop['Value'] for prop in account_details["accounts"][0]['Properties']
                    })
                    result.update({
                        'password': password
                    })
                ret.append(result if result else password)

        return ret
