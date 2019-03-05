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
import sys
import shelve
from ansible.plugins.lookup import LookupBase
from ansible.module_utils._text import to_bytes

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

# The module_utils path must be added to sys.path in order to import
# cyberark_connection. The module_utils path is relative to the path of this
# file.
module_utils_path = os.path.normpath(os.path.dirname(__file__) +
                                     '/../module_utils')
if module_utils_path is not None:
    sys.path.insert(0, module_utils_path)
    from cyberark_connection import CyberArkPasswordVaultConnector as pvc, \
        PWVAccountLocked, PWVAccountNoRequest, PWVRequestInvalid
    del sys.path[0]


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):

        if not isinstance(terms, list):
            terms = [terms]
        elif isinstance(terms, list) and len(terms) == 1:
            if isinstance(terms[0], list):
                terms = terms[0]

        result = []

        self.set_options(var_options=variables, direct=kwargs)
        safe = self._templar.template(self.get_option('safe'), fail_on_undefined=True)

        shelve_file = self.find_file_in_search_path(variables, 'files', '.cyberarkpwv', ignore_missing=True)

        if not shelve_file:
            shelve_file = "{}/.cyberarkpwv".format(self.find_file_in_search_path(variables, '', ''))

        cache = shelve.DbfilenameShelf(to_bytes(shelve_file))

        with pvc(cache, self._options) as vault:
            for term in terms:
                result.append(vault.get_password_for_account(keywords=term, safe=safe))

        return result
