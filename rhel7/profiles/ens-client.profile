documentation_complete: true

title: 'Spanish CCN-CERT ENS client machine'

description: |-
  This profile contains configuration checks for RHEL7/CentOS7 as a user's computer
  that align to the Spanish "Esquema Nacional de Seguridad", defined by CCN-CERT

  A copy of the CCN-STIC-619 document can be found in the CCN-CERT website:

  https://www.ccn-cert.cni.es/pdf/guias/series-ccn-stic/guias-de-acceso-publico-ccn-stic/3674-ccn-stic-619-implementacion-de-seguridad-sobre-centos7/file.html

  For questions, info, coments, patches, etc, contact me:
  Kuko Armas &lt;kuko@canarytek.com&gt;

extends: ens-server

selections:

# Grouped by ENS step script

  #### CCN-STIC-619_Paso_1_contrasena_grub
  - grub2_password

  #### CCN-STIC-619_Paso_6_limites_recursos_usuario
  ## Step 6: user limits
  # FIXME: lots of crazy limits!
  ## Login
  # FIXME: maxlogins 1?? No way, I will use 5
  - disable_users_coredumps
  - var_accounts_max_concurrent_login_sessions=5
  - accounts_max_concurrent_login_sessions
  - securetty_root_login_console_only
  - var_password_pam_unix_remember=5
  - accounts_password_pam_unix_remember
