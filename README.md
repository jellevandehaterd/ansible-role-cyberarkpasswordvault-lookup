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
        safe: 'MY_SAFE'
        password_lookup: "{{lookup('cyberarkpasswordvault', keywords='test', safe=safe, validate_certs=False)}}"
      tasks:
        - debug:
            var: password_lookup