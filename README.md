# cyberarkpasswordvault
Ansible lookup plugin for usage with the CyberArk Passwordvault rest API

Input configuration:

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
        help_text: "Ceck only if Cyberark has radius authentication enabled"
      
    required:
      - cyberark_url
      - cyberark_username
      - cyberark_password

Injector configuration:

    env:
      CYBERARK_URL: '{{ cyberark_url }}'
      CYBERARK_USERNAME: '{{ cyberark_username }}'
      CYBERARK_PASSWORD: '{{ cyberark_password }}'
      CYBERARK_USE_RADIUS_AUTHENTICATION: '{{ cyberark_use_radius_authentication }}'
      
  example:
  
    ---
    - hosts: localhost
      connection: local
      vars:
          cyberark_safe: "{{ my_safe_name }}"
          cyberark_connection:
             validate_certs: True
             url: '{{ my_cyberark_url}}'
             username: "{{ my_username }}"
             password: "{{ my_password }}"
             use_radius_authentication: False
             
      roles:
        - ansible-role-cyberarkpasswordvault-lookup
      tasks:
         - debug:
            msg: "{{lookup('cyberarkpasswordvault', 'test, localhost', passprops=True, errors='warn')}}"
    
        - debug:
            var: item
          loop: "{{query('cyberarkpasswordvault', keywords, passprops=True, errors='warn')}}"