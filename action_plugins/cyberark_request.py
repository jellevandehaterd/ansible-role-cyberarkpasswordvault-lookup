from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
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

from ansible.module_utils._text import to_text
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.plugins.action import ActionBase

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

try:
    from ansible.module_utils.cyberark_connection import CyberArkPasswordVaultConnector as pvc
except ImportError:
    import os
    import sys
    # The module_utils path must be added to sys.path in order to import
    # cyberark_connection. The module_utils path is relative to the path of this
    # file.
    module_utils_path = os.path.normpath(os.path.dirname(__file__) +
                                         '/../module_utils')
    if module_utils_path is not None:
        sys.path.insert(0, module_utils_path)
        from cyberark_connection import CyberArkPasswordVaultConnector as pvc
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

        keywords = self._templar.template(self._task.args.get('keywords', []))
        reason = self._templar.template(self._task.args.get('reason'), fail_on_undefined=True)
        wait = boolean(self._task.args.get('wait', True), strict=False)

        def has_failed(result, reason):
            result['failed'] = True
            result['msg'] = reason
            return result

        if not isinstance(keywords, list):  # Convert a single keyword to a list with 1 entry
            keywords = [keywords]
        elif isinstance(keywords, list) and len(keywords) == 1:
            if isinstance(keywords[0], list):
                keywords = keywords[0]

        if len(keywords) == 0:
            return has_failed(result, "keywords parameter should contain a single keyword or a list of keywords.")

        try:
            period = int(self._task.args.get('period'))
        except ValueError as e:
            result['failed'] = True
            result['msg'] = u"non-integer value given for request period: %s" % to_text(e)
            return result

        with pvc(self._task.args, self._templar) as vault:
            result['results'] = []
            for name in keywords:

                single_result = vault.request_password(name, vault, wait, reason, period)

                if 'failure' in single_result:
                    result['failed'] = True
                    result['msg'] = single_result['failure']
                    return result

                result['results'].append(single_result)

        return result
