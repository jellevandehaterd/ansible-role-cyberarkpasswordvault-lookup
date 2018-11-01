
# cyberarkpasswordvault 
Role to add Ansible lookup plugin for usage with the CyberArk Passwordvault REST API

Provided Plugin

- **cyberarkpasswordvault**: Lookup module for CyberArk credential retrieval using CyberArk Passwordvault REST API. 

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

1) Basic usage 
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
        msg: "Username: {{item.passprops.username}}, Passord: {{ item.password }}"
      with_items: "{{lookup('cyberarkpasswordvault', 'one, foo', 'two, bar', passprops=True)}}"

    - debug:
        var: item
      loop: "{{query('cyberarkpasswordvault', keywords, passprops=True)}}"
```

2) Usage password lookup in inventory

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
