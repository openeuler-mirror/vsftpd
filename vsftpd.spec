%define generator_dir %{_prefix}/lib/systemd/system-generators

Name:          vsftpd
Version:       3.0.3
Release:       32
Summary:       It is a secure FTP server for Unix-like systems
# OpenSSL link exception
License:       GPLv2 with exceptions
URL:           https://security.appspot.com/vsftpd.html
Source0:       https://security.appspot.com/downloads/%{name}-%{version}.tar.gz
Source1:       vsftpd.xinetd
Source2:       vsftpd.pam
Source3:       vsftpd.ftpusers
Source4:       vsftpd.user_list
Source5:       vsftpd_conf_migrate.sh
Source6:       vsftpd.service
Source7:       vsftpd@.service
Source8:       vsftpd.target
Source9:       vsftpd-generator
Source10:      vsftpd.default.log
BuildRequires: pam-devel libcap-devel openssl-devel systemd vim make gcc
Requires:      logrotate vsftpd-help

#patches from redhat see descriptions in each patch file for detailed information
Patch1:        0001-Don-t-use-the-provided-script-to-locate-libraries.patch
Patch2:        0002-Enable-build-with-SSL.patch
Patch3:        0003-Enable-build-with-TCP-Wrapper.patch
Patch4:        0004-Use-etc-vsftpd-dir-for-config-files-instead-of-etc.patch
Patch5:        0005-Use-hostname-when-calling-PAM-authentication-module.patch
Patch6:        0006-Close-stdin-out-err-before-listening-for-incoming-co.patch
Patch7:        0007-Make-filename-filters-smarter.patch
Patch8:        0008-Write-denied-logins-into-the-log.patch
Patch9:        0009-Trim-whitespaces-when-reading-configuration.patch
Patch10:       0010-Improve-daemonizing.patch
Patch11:       0011-Fix-listing-with-more-than-one-star.patch
Patch12:       0012-Replace-syscall-__NR_clone-.-with-clone.patch
Patch13:       0013-Extend-man-pages-with-systemd-info.patch
Patch14:       0014-Add-support-for-square-brackets-in-ls.patch
Patch15:       0015-Listen-on-IPv6-by-default.patch
Patch16:       0016-Increase-VSFTP_AS_LIMIT-from-200UL-to-400UL.patch
Patch17:       0017-Fix-an-issue-with-timestamps-during-DST.patch
Patch18:       0018-Change-the-default-log-file-in-configuration.patch
Patch19:       0019-Introduce-reverse_lookup_enable-option.patch
Patch20:       0020-Use-unsigned-int-for-uid-and-gid-representation.patch
Patch21:       0021-Introduce-support-for-DHE-based-cipher-suites.patch
Patch22:       0022-Introduce-support-for-EDDHE-based-cipher-suites.patch
Patch23:       0023-Add-documentation-for-isolate_-options.-Correct-defa.patch
Patch24:       0024-Introduce-new-return-value-450.patch
Patch25:       0025-Improve-local_max_rate-option.patch
Patch26:       0026-Prevent-hanging-in-SIGCHLD-handler.patch
Patch27:       0027-Delete-files-when-upload-fails.patch
Patch28:       0028-Fix-man-page-rendering.patch
Patch29:       0029-Fix-segfault-in-config-file-parser.patch
Patch30:       0030-Fix-logging-into-syslog-when-enabled-in-config.patch
Patch31:       0031-Fix-question-mark-wildcard-withing-a-file-name.patch
Patch32:       0032-Propagate-errors-from-nfs-with-quota-to-client.patch
Patch33:       0033-Introduce-TLSv1.1-and-TLSv1.2-options.patch
Patch34:       0034-Turn-off-seccomp-sandbox-because-it-is-too-strict.patch
Patch35:       0035-Modify-DH-enablement-patch-to-build-with-OpenSSL-1.1.patch
Patch36:       0036-Redefine-VSFTP_COMMAND_FD-to-1.patch
Patch37:       0037-Document-the-relationship-of-text_userdb_names-and-c.patch
Patch38:       0038-Document-allow_writeable_chroot-in-the-man-page.patch
Patch39:       0039-Improve-documentation-of-ASCII-mode-in-the-man-page.patch
Patch40:       0040-Use-system-wide-crypto-policy.patch
Patch41:       0041-Document-the-new-default-for-ssl_ciphers-in-the-man-.patch
Patch42:       0042-When-handling-FEAT-command-check-ssl_tlsv1_1-and-ssl.patch
Patch43:       0043-Enable-only-TLSv1.2-by-default.patch
Patch44:       0044-Disable-anonymous_enable-in-default-config-file.patch
Patch45:       0045-Expand-explanation-of-ascii_-options-behaviour-in-ma.patch
Patch46:       0046-vsftpd.conf-Refer-to-the-man-page-regarding-the-asci.patch
Patch47:       0047-Disable-tcp_wrappers-support.patch
Patch48:       0048-Fix-default-value-of-strict_ssl_read_eof-in-man-page.patch
Patch49:       0049-Add-new-filename-generation-algorithm-for-STOU-comma.patch
Patch50:       0050-Don-t-link-with-libnsl.patch
Patch51:       0051-Improve-documentation-of-better_stou-in-the-man-page.patch
Patch52:       0052-Fix-rDNS-with-IPv6.patch
Patch53:       0053-Always-do-chdir-after-chroot.patch
Patch54:       0054-vsf_sysutil_rcvtimeo-Check-return-value-of-setsockop.patch
Patch55:       0055-vsf_sysutil_get_tz-Check-the-return-value-of-syscall.patch
Patch56:       0056-Log-die-calls-to-syslog.patch
Patch57:       0057-Improve-error-message-when-max-number-of-bind-attemp.patch
Patch58:       0058-Make-the-max-number-of-bind-retries-tunable.patch
Patch59:       0059-Fix-SEGFAULT-when-running-in-a-container-as-PID-1.patch
Patch60:       0001-Move-closing-standard-FDs-after-listen.patch
Patch61:       0002-Prevent-recursion-in-bug.patch
Patch62:       0001-Set-s_uwtmp_inserted-only-after-record-insertion-rem.patch
Patch63:       0002-Repeat-pututxline-if-it-fails-with-EINTR.patch
Patch64:       0001-Repeat-pututxline-until-it-succeeds-if-it-fails-with.patch
Patch65:       0001-Fix-timestamp-handling-in-MDTM.patch
Patch66:       0002-Drop-an-unused-global-variable.patch
Patch67:       0001-Remove-a-hint-about-the-ftp_home_dir-SELinux-boolean.patch
Patch68:       fix-str_open.patch

Patch9000:     bugfix-change-the-default-value-of-tunable_reverse_lookup_e.patch

%description
Vsftpd, (or very secure FTP daemon), is an FTP server for Unix-like systems, including Linux.
It is licensed under the GNU General Public License. It supports IPv6 and SSL.
Vsftpd supports explicit (since 2.0.0) and implicit (since 2.1.0) FTPS.

%package help
Summary: Help package for package %{name}

%description help
This package contains man directory manuals.

%prep
%autosetup -p1

%build
make CFLAGS="$RPM_OPT_FLAGS -fpie -pipe -Wextra -Werror" LINK="-pie -lssl" %{?_smp_mflags}

%install
install -d %{buildroot}{%{_unitdir},%{generator_dir},%{_var}/ftp/pub}
install -Dm755 vsftpd  %{buildroot}%{_sbindir}/vsftpd
install -Dm600 vsftpd.conf %{buildroot}%{_sysconfdir}/vsftpd/vsftpd.conf
install -Dm644 vsftpd.conf.5 %{buildroot}/%{_mandir}/man5/vsftpd.conf.5
install -Dm644 vsftpd.8 %{buildroot}/%{_mandir}/man8/vsftpd.8
install -Dm644 %{SOURCE10} %{buildroot}%{_sysconfdir}/logrotate.d/vsftpd
install -Dm644 %{SOURCE2} %{buildroot}%{_sysconfdir}/pam.d/vsftpd
install -m600 %{SOURCE3} %{buildroot}%{_sysconfdir}/vsftpd/ftpusers
install -m600 %{SOURCE4} %{buildroot}%{_sysconfdir}/vsftpd/user_list
install -m744 %{SOURCE5} %{buildroot}%{_sysconfdir}/vsftpd/vsftpd_conf_migrate.sh
install -m644 {%{SOURCE6},%{SOURCE7},%{SOURCE8}} %{buildroot}%{_unitdir}
install -m755 %{SOURCE9} %{buildroot}%{generator_dir}
cp -f %{SOURCE1} ./

%post
%systemd_post vsftpd.service

%preun
%systemd_preun vsftpd.service
%systemd_preun vsftpd.target

%postun
%systemd_postun_with_restart vsftpd.service

%files
%doc LICENSE README.security COPYING SECURITY/
%{_sysconfdir}/vsftpd/vsftpd_conf_migrate.sh
%config(noreplace) %{_sysconfdir}/vsftpd/ftpusers
%config(noreplace) %{_sysconfdir}/vsftpd/user_list
%config(noreplace) %{_sysconfdir}/vsftpd/vsftpd.conf
%config(noreplace) %{_sysconfdir}/pam.d/vsftpd
%config(noreplace) %{_sysconfdir}/logrotate.d/vsftpd
%{_unitdir}/*
%{generator_dir}/*
%{_sbindir}/vsftpd
%{_sysconfdir}/vsftpd/*
%{_var}/ftp

%files help
%doc FAQ INSTALL BUGS AUDIT Changelog README REWARD
%doc SPEED TODO BENCHMARKS EXAMPLE/ TUNING SIZE vsftpd.xinetd
%{_mandir}/man5/vsftpd.conf.*
%{_mandir}/man8/vsftpd.*

%changelog
* Sat Jan 30 2021 zhuqingfu <zhuqingfu1@huawei.com> - 3.0.3-32
- Type:bugfix
- Id:NA
- SUG:NA
- DESC: add patches for vsftpd

* Fri Nov 06 2020 gaihuiying <gaihuiying1@huawei.com> - 3.0.3-31
- Type:requirement
- Id:NA
- SUG:NA
- DESC: add vsftpd-help dependency for vsftpd

* Fri Dec 20 2019 openEuler Buildteam <buildteam@openeuler.org> - 3.0.3-30
- Type:bugfix
- Id:NA
- SUG:NA
- DESC: add vsftpd.default.log

* Tue Sep 10 2019 huzhiyu<huzhiyu1@huawei.com> - 3.0.3-29
- Package init
