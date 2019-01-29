
# cyberarkpasswordvault
Role to add plugins for usage with the CyberArk Passwordvault REST API

The plugins in this role provide the following:

- `cyberarkpasswordvault` lookup plugin for credentials without authorisation flow.
- `pwv_request` task for credentials with an authorisation flow
- `format_list` filter, allows for the formatting of a list of strings
- `remove_prefix` filter, removes a static prefix on a string
- `remove_prefix_list` filter, removes a static prefix on a list of strings


# Variables

For usage of this lookup plugin a connection needs to be made with cyberark.
This can be done using a [**custom credential**](#ansible-tower-custom-credential) in Ansible Tower or
using Ansible Vault.

```yaml
# ansible vault
cyberark_safe: "MySafeName"
cyberark_connection:
  validate_certs: True
  url: 'https://components.cyberarkdemo.com'
  username: "my_rest_username"
  password: "my_very_secret_password"
  use_radius_authentication: False
```

# Examples
Below examples assume the variables specified above are set.

1) Basic usage for credentials (no authorsation flow)
```yaml
- hosts: webservers
  vars:
    keywords:
      - 'ansible@webserver-1'
      - 'ansible@webserver-2'
  roles:
      - ansible-role-cyberarkpasswordvault-lookup
  tasks:
    - name: Request password for keyword 'foo, bar'
      debug:
        msg: "{{lookup('cyberarkpasswordvault', 'foo, bar')}}"

    - name: Request passwords and password properties(passprops) for multiple accounts.
      debug:
        msg: "Username: {{item.passprops.username}}, Password: {{ item.password }}"
      with_items: "{{lookup('cyberarkpasswordvault', 'one, foo', 'two, bar', passprops=True)}}"

    - debug:
        var: item
      loop: "{{query('cyberarkpasswordvault', keywords, passprops=True)}}"
```

2) Usage password lookup in inventory (no authorisation flow)

The INI way:
```yaml
#inventory file

mail.example.com

[webservers]
foo.example.com
bar.example.com

[dbservers]
one.example.com
two.example.com
three.example.com

#All servers in this example are accessible using the same username/password for Ansible ssh access
[all:vars]
ansible_user=user_whith_ssh_access
ansible_ssh_pass="{{lookup('cyberarkpasswordvault', 'keywords to retreive ssh credentials', safe='CySafeName')['password']}}"
```

The YAML version:
```yaml
all:
  hosts:
    mail.example.com:
  vars:
    ansible_user: "ansible"
    ansible_ssh_pass: "{{lookup('cyberarkpasswordvault', inventory_hostname + ' ansible', safe=safe)['password']}}"
  children:
    webservers:
      hosts:
        foo.example.com:
        bar.example.com:
    dbservers:
      hosts:
        one.example.com:
        two.example.com:
        three.example.com:
```

3) Request the password of an NPA credentials and use it to login to the system (with authorisation flow)

This example requests the credentials for the `ansible_log4all` NPA and uses it to login to systems.

```yaml
- name: Run whoami on all systems
  hosts: all
  gather_facts: false
  roles:
  - ansible-role-cyberarkpasswordvault-lookup
  vars_prompt:
    - name: "pwv_period"
      prompt: "How long do we need the password (in seconds)?"
      default: 3600
    - name: "pwv_reason"
      prompt: "Reason for passwordvault request"
    - name: "corpkey_username"
      prompt: your corporation key (used for ssh and passwordvault)
    - name: "corpkey_password"
      prompt: your corporation password (used for ssh and passwordvault)
      private: true
  vars:
    npa_account: "ansible_log4all"
  tasks:
  - name: Request the credentials for the npa account
    pwv_request:
      keywords: "{{npa_account}}"
      reason: "{{pwv_reason}}"
      period: "{{pwv_period}}"
      username: "{{corpkey_username}}"
      password: "{{corpkey_password}}"
      wait: true
    register: pwv_result
    become: false
    delegate_to: localhost
    run_once: yes
  - name: set the ssh credentials to the npa account for each host
    set_fact:
      ansible_ssh_user: "{{npa_account}}"
      ansible_ssh_pass: "{{ pwv_result.results[0].password}}"
    no_log: true
  - name: whoami
    command: whoami
```


4) Request root password for privilege escalation but use corpkey to login.

```yaml
- name: Run whoami on all systems
  hosts: all
  gather_facts: false
  roles:
  - ansible-role-cyberarkpasswordvault-lookup
  vars_prompt:
    - name: "pwv_period"
      prompt: "How long do we need the password (in seconds)?"
      default: 3600
    - name: "pwv_reason"
      prompt: "Reason for passwordvault request"
    - name: "corpkey_username"
      prompt: your corporation key (used for ssh and passwordvault)
    - name: "corpkey_password"
      prompt: your corporation password (used for ssh and passwordvault)
      private: true
  tasks:
  - name: Request password from the passwordvault
    pwv_request:
      keywords: "{{ ansible_play_hosts | format_list('root@%s') }}"
      reason: "{{pwv_reason}}"
      period: "{{pwv_period}}"
      username: "{{corpkey_username}}"
      password: "{{corpkey_password}}"
      wait: true
    register: pwv_result
    become: false
    delegate_to: localhost
    run_once: yes
  - name: Set the ssh and become password for each host
    set_fact:
      ansible_ssh_user: "{{ corpkey_username }}"
      ansible_ssh_pass: "{{ corpkey_password }}"
      ansible_become_pass: "{{item.password}}"
    delegate_to: "{{ item.keyword | remove_prefix('root@') }}"
    with_items: "{{ pwv_result.results }}"
    run_once: yes
    no_log: true
  - name: whoami
    command: whoami
```


# Ansible Tower Custom Credential

In ansible tower a [custom credential type](https://docs.ansible.com/ansible-tower/latest/html/userguide/credential_types.html)
can be added using the yaml provided below.

Input configuration:
```yaml
fields:
  - type: string
    id: cyberark_url
    label: Cyberark url
  - type: string
    id: cyberark_username
    label: Cyberark username
  - type: string
    id: cyberark_password
    label: Cyberark password
    secret: true
  - type: boolean
    id: cyberark_use_radius_authentication
    label: Cyberark use radius authentication
    help_text: "Check only if Cyberark has radius authentication enabled"

required:
  - cyberark_url
  - cyberark_username
  - cyberark_password
```


Injector configuration:
```yaml
env:
  CYBERARK_URL: '{{ cyberark_url }}'
  CYBERARK_USERNAME: '{{ cyberark_username }}'
  CYBERARK_PASSWORD: '{{ cyberark_password }}'
  CYBERARK_USE_RADIUS_AUTHENTICATION: '{{ cyberark_use_radius_authentication }}'
```
