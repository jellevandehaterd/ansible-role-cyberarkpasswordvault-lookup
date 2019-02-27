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

import sys
import os.path
from ansible.errors import AnsibleError
from ansible.module_utils._text import to_text, to_native
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.plugins.action import ActionBase

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


class ActionModule(ActionBase):

    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        """
        Action plugin handler for creating password vault requests.
        """

        self._supports_check_mode = True
        self._supports_async = False

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        # url = self._task.args.get('url', 'https://pwv.europe.intranet')
        #
        # username = self._task.args.get('username')
        # password = self._task.args.get('password')
        #
        # use_radius_authentication = boolean(self._task.args.get('use_radius_authentication', True), strict=False)
        # validate_certs = boolean(self._task.args.get('validate_certs', True), strict=False)
        # use_proxy = boolean(self._task.args.get('use_proxy', True), strict=False)

        keywords = self._task.args.get('keywords', [])
        safe = self._task.args.get('safe')
        reason = self._task.args.get('reason')
        wait = boolean(self._task.args.get('wait', True), strict=False)

        def has_failed(result, reason):
            result['failed'] = True
            result['msg'] = reason
            return result

        if not username:
            return has_failed(result, "username parameter should contain the loginname for the passwordvault")

        if not password:
            return has_failed(result, "password parameter should contain the password for the passwordvault")

        if isinstance(keywords, str):  # Convert a single keyword to a list with 1 entry
            keywords = [keywords]

        if len(keywords) == 0:
            return has_failed(result, "keywords parameter should contain a single keyword or a list of keywords.")

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

        with pvc(options) as vault:
            result['results'] = []
            for name in keywords:
            
                single_result = self.request_password(name, safe, vault, wait, reason, period)

                if 'failure' in single_result:
                    result['failed'] = True
                    result['msg'] = single_result['failure']
                    return result

                result['results'].append(single_result)

        return result

    def request_password(self, name, safe, vault, wait, reason, period):

        account_id, account_details = vault.get_single_account(
            safe=self._templar.template(safe, fail_on_undefined=True),
            keyword=self._templar.template(name, fail_on_undefined=True),
        )

        display.v("account_details: %s " % account_details)

        try:
            request = vault.get_request(name, safe)
            if not request:
                vault.create_request(account_id, reason, period)
                request = vault.get_request(name, safe)
        except PWVRequestInvalid as e:
            raise AnsibleError("could create request: %s" % e)

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
