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
options :
  cyberark_url:
    description: url of cyberark PAS.
    env: 
     - name: CYBERARK_URL
  cyberark_username:
    description: cyberark authentication username.
    env:
      - name: CYBERARK_USERNAME
    default: admin
  cyberark_password:
    description: cyberark authentication password.
    env:
      - name: CYBERARK_PASSWORD
    default: admin
  cyberark_use_radius_authentication:
    description: use radius for cyberark authentication.
    env:
      - name: CYBERARK_USE_RADIUS_AUTHENTICATION
    default: false
  safe:
    description: the name of the safe to be queried.
    default: None
  keywords:
    description: keywords to limit the resultset to 1.
    default: None
  validate_certs:
    description: Flag to control SSL certificate validation
    type: boolean
    default: True
  use_proxy:
    description: Flag to control if the lookup will observe HTTP proxy environment variables when present.
    type: boolean
    default: True   
"""

EXAMPLES = """
  
"""

RETURN = """
  password:
    description:
      - The actual value stored
  passprops:
    description: properties assigned to the entry
    type: dictionary
  passwordchangeinprocess:
    description: did the password change?
"""

import os
import json

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
ANSIBLE_CYBERARK_APP_ID = os.getenv('CYBERARK_APP_ID', None)
ANSIBLE_CYBERARK_USE_RADIUS_AUTHENTICATION = os.getenv('CYBERARK_USE_RADIUS_AUTHENTICATION', False)


class CyberArkPasswordVaultConnector:

    def __init__(self, options, **kwargs):
        """Handles the authentication against the API and calls the appropriate API
        endpoints.
        """
        self._session_token = None
        self.cyberark_url = options.get('cyberark_url', ANSIBLE_CYBERARK_URL)
        self.cyberark_username = options.get('cyberark_username', ANSIBLE_CYBERARK_USERNAME)
        self.cyberark_password = options.get('cyberark_password', ANSIBLE_CYBERARK_PASSWORD)
        self.cyberark_app_id = options.get('cyberark_app_id', ANSIBLE_CYBERARK_APP_ID)
        self.cyberark_use_radius_authentication = options.get('cyberark_use_radius_authentication', ANSIBLE_CYBERARK_USE_RADIUS_AUTHENTICATION)
        self._kwargs = kwargs

    def __enter__(self):
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
                #'x-api-key': '106ab2b87ed945118f3e67be74ce06b1'
            }

        if self._session_token is not None:
            headers['Authorization'] = self._session_token

        url = '{base_url}/PasswordVault/{api_endpoint}'.format(
            base_url=self.cyberark_url,
            api_endpoint=api_endpoint
        )
        display.vvvv("CyberArk lookup: connecting to API endpoint %s" % url)

        if params:
            params = urlencode(params.items())
            url = '{url}?{querystring}'.format(url=url, querystring=params)
        try:
            response = open_url(url=url, data=data, headers=headers, method=method, **self._kwargs)
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
        payload = json.dumps({
            "username": self.cyberark_username,
            "password": self.cyberark_password,
            "useRadiusAuthentication": "{radius}".format(radius=self.cyberark_use_radius_authentication).lower(),
            "connectionNumber": "1"
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

        self.set_options(direct=kwargs)
        _kwargs = {
            'validate_certs': self.get_option('validate_certs'),
            'use_proxy': self.get_option('use_proxy')
        }
        display.vvvv("terms\n%s" % terms)
        with CyberArkPasswordVaultConnector(self._options, **_kwargs) as vault:

            account_details = vault.get_account_details(
                safe=self.get_option('safe'),
                keywords=self.get_option('keywords'),
            )
            display.vvvv("%s" % account_details)
            if account_details["Count"] != 1:
                raise AnsibleError("Search result contains no accounts or more than 1 account")

            password = vault.get_password_value(
                account_details["accounts"][0]["AccountID"]
            )

        return [password]
