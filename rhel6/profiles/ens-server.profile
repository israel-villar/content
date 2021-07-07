documentation_complete: true

title: 'Spanish CCN-CERT ENS Server'

description: |-
  This profile contains configuration for a RHEL6/CentOS6 server to comply with requirements defined in the spanish "Esquema Nacional de Seguridad" (ENS).

  RHEL6 is not included in the supported OS in ENS, su this setup is based on CentOS7 setup (see rhel7 ens-server profile) 
  This profile is basically the same as rhel7's ens-server, I just commented out with "#-" all requirements not supported in rhel6

  For questions, info, coments, patches, etc, contact me:
  Kuko Armas &lt;kuko@canarytek.com&gt;

selections:

# Grouped by ENS step script

  #### CCN-STIC-619_Paso_1_contrasena_grub
  #- grub2_password

  #### Extended CCN-STIC-619_Paso_2_parametros_del_kernel
  ## Network Settings
  # FIXME: ENS ignores ALL icmp echo request, NONSENSE!!! (net.ipv4.icmp_echo_ignore_all)
  # FIXME: ENS disable TCP timestamps. No other standard does (net.ipv4.tcp_timestamps)
  # FIXME: ENS disables ipv6 completely!!! I refuse to do so!
  - sysctl_net_ipv6_conf_all_accept_ra
  - sysctl_net_ipv6_conf_default_accept_ra
  - sysctl_net_ipv4_conf_all_accept_redirects
  - sysctl_net_ipv4_conf_default_accept_redirects
  - sysctl_net_ipv6_conf_all_accept_redirects
  - sysctl_net_ipv6_conf_default_accept_redirects
  - sysctl_net_ipv4_conf_all_accept_source_route
  - sysctl_net_ipv4_conf_default_accept_source_route
  - sysctl_net_ipv6_conf_all_accept_source_route
  - sysctl_net_ipv6_conf_default_accept_source_route
  - sysctl_net_ipv4_conf_all_secure_redirects
  - sysctl_net_ipv4_conf_default_secure_redirects
  - sysctl_net_ipv4_conf_all_send_redirects
  - sysctl_net_ipv4_conf_default_send_redirects
  - sysctl_net_ipv4_conf_all_log_martians
#- - sysctl_net_ipv4_conf_default_log_martians
  - sysctl_net_ipv4_conf_all_rp_filter
  - sysctl_net_ipv4_conf_default_rp_filter
  - sysctl_net_ipv4_icmp_ignore_bogus_error_responses
  - sysctl_net_ipv4_icmp_echo_ignore_broadcasts
  - sysctl_net_ipv4_ip_forward
  - sysctl_net_ipv4_tcp_syncookies

  ## Security Settings
  - sysctl_kernel_kptr_restrict
  - sysctl_kernel_dmesg_restrict
  - sysctl_kernel_kexec_load_disabled
  - sysctl_kernel_yama_ptrace_scope
  - sysctl_fs_suid_dumpable

  ## File System Settings
  - sysctl_fs_protected_hardlinks
  - sysctl_fs_protected_symlinks
 
  # FIXME: ENS sets net.ipv4.tcp_max_syn_backlog = 1280. No other standard does

  #### Extended CCN-STIC-619_Paso_3_reglas_audit
  ### Audit: More complete than ENS, inspired on ncp profile
  - service_auditd_enabled
  - var_auditd_flush=incremental_async
  - auditd_data_retention_flush
  - auditd_audispd_syslog_plugin_activated
  - var_auditd_action_mail_acct=root
  - var_auditd_admin_space_left_action=single
  - var_auditd_max_log_file_action=rotate
  - var_auditd_max_log_file=6
  - var_auditd_num_logs=5
  - var_auditd_space_left_action=email
  - auditd_data_retention_action_mail_acct
  - auditd_data_retention_admin_space_left_action
  - auditd_data_retention_max_log_file_action
  - auditd_data_retention_max_log_file
  - auditd_data_retention_num_logs
  - auditd_data_retention_space_left_action
  - file_permissions_var_log_audit
  - audit_rules_dac_modification_chmod
  - audit_rules_dac_modification_chown
  - audit_rules_dac_modification_fchmodat
  - audit_rules_dac_modification_fchmod
  - audit_rules_dac_modification_fchownat
  - audit_rules_dac_modification_fchown
  - audit_rules_dac_modification_fremovexattr
  - audit_rules_dac_modification_fsetxattr
  - audit_rules_dac_modification_lchown
  - audit_rules_dac_modification_lremovexattr
  - audit_rules_dac_modification_lsetxattr
  - audit_rules_dac_modification_removexattr
  - audit_rules_dac_modification_setxattr
#-  - audit_rules_execution_chcon
#-  - audit_rules_execution_restorecon
#-  - audit_rules_execution_semanage
#-  - audit_rules_execution_setsebool
#-  - audit_rules_file_deletion_events_renameat
#-  - audit_rules_file_deletion_events_rename
#-  - audit_rules_file_deletion_events_rmdir
#-  - audit_rules_file_deletion_events
#-  - audit_rules_file_deletion_events_unlinkat
#-  - audit_rules_file_deletion_events_unlink
  - audit_rules_immutable
#-  - audit_rules_kernel_module_loading_delete
#-  - audit_rules_kernel_module_loading_init
  - audit_rules_login_events_faillock
  - audit_rules_login_events_lastlog
  - audit_rules_login_events_tallylog
  - audit_rules_mac_modification
  - audit_rules_media_export
  - audit_rules_networkconfig_modification
#-  - audit_rules_privileged_commands_chage
#-  - audit_rules_privileged_commands_chsh
#-  - audit_rules_privileged_commands_crontab
#-  - audit_rules_privileged_commands_gpasswd
#-  - audit_rules_privileged_commands_newgrp
#-  - audit_rules_privileged_commands_pam_timestamp_check
#-  - audit_rules_privileged_commands_passwd
#-  - audit_rules_privileged_commands_postdrop
#-  - audit_rules_privileged_commands_postqueue
  - audit_rules_privileged_commands
#-  - audit_rules_privileged_commands_ssh_keysign
#-  - audit_rules_privileged_commands_sudoedit
#-  - audit_rules_privileged_commands_sudo
#-  - audit_rules_privileged_commands_su
#-  - audit_rules_privileged_commands_umount
#-  - audit_rules_privileged_commands_unix_chkpwd
#-  - audit_rules_privileged_commands_userhelper
  - audit_rules_session_events
  - audit_rules_sysadmin_actions
#-  - audit_rules_system_shutdown
  - audit_rules_time_adjtimex
  - audit_rules_time_clock_settime
  - audit_rules_time_settimeofday
  - audit_rules_time_stime
  - audit_rules_time_watch_localtime
  - audit_rules_unsuccessful_file_modification_creat
  - audit_rules_unsuccessful_file_modification_ftruncate
  - audit_rules_unsuccessful_file_modification_openat
  - audit_rules_unsuccessful_file_modification_open_by_handle_at
  - audit_rules_unsuccessful_file_modification_open
  - audit_rules_unsuccessful_file_modification_truncate
  - audit_rules_usergroup_modification_group
  - audit_rules_usergroup_modification_gshadow
#-  - audit_rules_usergroup_modification_opasswd
  - audit_rules_usergroup_modification_passwd
  - audit_rules_usergroup_modification_shadow
  - file_ownership_var_log_audit
#-  - sebool_auditadm_exec_content

  #### CCN-STIC-619_Paso_4a_repositorio_inst
  ## Step 4a: install tools: aide and firewalld
  ## FIXME: ENS uses iptables-service, better use firewalld
  # aide
  - aide_build_database
  - aide_periodic_cron_checking
#- - aide_scan_notification
  #- aide_use_fips_hashes
#-  - aide_verify_acls
#-  - aide_verify_ext_attributes
  - package_aide_installed

  # firewalld
#-  - package_firewalld_installed
  #- firewalld_sshd_port_enabled
#-  - service_firewalld_enabled

  #### CCN-STIC-619_Paso_4b_repositorio_local
  ## Step 4b: security patches up to date
  - security_patches_up_to_date

  #### CCN-STIC-619_Paso_5_limitacion_usb
  ## Step 5: FIXME:  config usbguard
  - package_usbguard_installed  

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

  # Banners
  - login_banner_text=ens_banner
  - banner_etc_issue

  # umask 027
  - var_accounts_user_umask=027
  - accounts_umask_etc_login_defs
  - accounts_umask_etc_profile
  - accounts_umask_etc_bashrc
  - accounts_umask_etc_csh_cshrc
#-  - accounts_umask_interactive_users

  #### CCN-STIC-619_Paso_7_herramientas_servicios_y_demonios_innecesarios
  ## FIXME: Sorry, I won't disable nfs
  - kernel_module_freevxfs_disabled
  - kernel_module_hfs_disabled
  - kernel_module_hfsplus_disabled
  - kernel_module_jffs2_disabled
  - kernel_module_squashfs_disabled
  - package_rsh_removed
  - package_rsh-server_removed
  - package_talk_removed
  - package_talk-server_removed
  - package_telnet_removed
  - package_telnet-server_removed
  - package_xinetd_removed
  - package_ypbind_removed
  - package_ypserv_removed
 
  #### CCN-STIC-619_Paso_8_desinstalar_usuarios_innecesarios
  ## NO WAY!

  #### CCN-STIC-619_Paso_9_paquetes_huerfanos
  ## Nothing to do, really

  #### CCN-STIC-619_Paso_10_caducidad_complejidad_contraseñas
  ## Configure Minimum Password Length to 12 Characters
  - var_accounts_password_minlen_login_defs=12
  - var_password_pam_minlen=12
#-  - accounts_password_pam_minlen
  - var_password_pam_difok=8
#-  - accounts_password_pam_difok
  - var_password_pam_minclass=4
#-  - accounts_password_pam_minclass
  ## Require at Least 1 Special Character in Password
  - var_password_pam_ocredit=1
#-  - accounts_password_pam_ocredit

  ## Require at Least 1 Numeric Character in Password
  - var_password_pam_dcredit=1
#-  - accounts_password_pam_dcredit

  ## Require at Least 1 Uppercase Character in Password
  - var_password_pam_ucredit=1
#-  - accounts_password_pam_ucredit

  ## Require at Least 1 Lowercase Character in Password
  - var_password_pam_lcredit=1
#-  - accounts_password_pam_lcredit

  ## Passwd expiration
#-  - var_account_disable_post_pw_expiration=35
  - var_accounts_maximum_age_login_defs=90
  - var_accounts_minimum_age_login_defs=2
  - var_accounts_password_warn_age_login_defs=7
#-  - account_disable_post_pw_expiration
  - accounts_maximum_age_login_defs
  - accounts_minimum_age_login_defs
  - accounts_password_warn_age_login_defs

  ## Session timeouts 
  - var_accounts_tmout=10_min
  - accounts_tmout

  #### CCN-STIC-619_Paso_11_intentos_fallidos
  ## Set Maximum Number of Authentication Failures to 3 Within 15 Minutes. Lock for 30 min
  - var_accounts_passwords_pam_faillock_deny=3
  - accounts_passwords_pam_faillock_deny
  - var_accounts_passwords_pam_faillock_fail_interval=900
  - accounts_passwords_pam_faillock_interval
  - var_accounts_passwords_pam_faillock_unlock_time=1800
  - accounts_passwords_pam_faillock_unlock_time

  #### CCN-STIC-619_Paso_12_Permisos_particiones
  ## Partitioning
  #- mount_option_home_nodev
  #- mount_option_home_nosuid
  #- mount_option_tmp_nodev
  #- mount_option_tmp_noexec
  #- mount_option_tmp_nosuid
  #- mount_option_var_tmp_nodev
  #- mount_option_var_tmp_noexec
  #- mount_option_var_tmp_nosuid
  #- mount_option_dev_shm_nodev
  #- mount_option_dev_shm_noexec
  #- mount_option_dev_shm_nosuid


  ### Additional settings (Not in ENS)
  - no_rsh_trust_files
  - service_crond_enabled

  - service_rexec_disabled
  - service_rlogin_disabled
  - service_rsh_disabled
  - service_telnet_disabled
  - service_xinetd_disabled
  - service_ypbind_disabled
#-  - service_zebra_disabled

  ### Services
  # sshd
  - sshd_required=yes
#-  - service_sshd_enabled
#-  - sshd_disable_root_login
  #- sshd_disable_root_password_login
#-  - sshd_print_last_log
  - sshd_allow_only_protocol2
  - sshd_disable_compression
  - sshd_do_not_permit_user_env
  # rhel6 only support yes (not sandbox)
  - var_sshd_priv_separation=yes
  - sshd_use_priv_separation
  - sshd_enable_strictmodes
  - disable_host_auth
  - sshd_disable_empty_passwords
  - no_empty_passwords
  - sshd_disable_kerb_auth
  - sshd_disable_gssapi_auth
  - sshd_set_keepalive
  - sshd_enable_warning_banner
  - sshd_disable_rhosts_rsa
  #- sshd_use_approved_ciphers
  #- sshd_use_approved_macs
  - sshd_idle_timeout_value=10_minutes
  - sshd_set_idle_timeout

  # Time Server

  ### systemd
  - disable_ctrlaltdel_reboot
#-  - disable_ctrlaltdel_burstaction
#-  - service_debug-shell_disabled
  - service_kdump_disabled
  - service_autofs_disabled

  ### Software update
  - ensure_gpgcheck_globally_activated
#-  - ensure_gpgcheck_local_packages
  - ensure_gpgcheck_never_disabled

  ### Kernel Config
  ## Boot prompt
  #- package_dracut-fips_installed
#-  - grub2_audit_argument
#-  - grub2_audit_backlog_limit_argument
#-  - grub2_slub_debug_argument
#-  - grub2_page_poison_argument
#-  - grub2_vsyscall_argument


  ### Module Blacklist
  - kernel_module_usb-storage_disabled
  - kernel_module_cramfs_disabled
  - kernel_module_bluetooth_disabled
  - kernel_module_dccp_disabled
  - kernel_module_sctp_disabled

  ### Remove Prohibited Packages
  - package_abrt_removed

  ## Disable Unauthenticated Login (such as Guest Accounts)
  ## FIA_AFL.1
  - require_singleuser_auth
#-  - grub2_disable_interactive_boot
#-  - grub2_uefi_password


  ###  SELinux Configuration
  # Ensure SELinux is Enforcing
  - var_selinux_state=enforcing
  - selinux_state

  # Configure SELinux Policy
  - var_selinux_policy_name=targeted
  - selinux_policytype
