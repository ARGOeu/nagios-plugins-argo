# sitelib
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%define dir /usr/libexec/argo-monitoring/probes/argo

Name: nagios-plugins-argo
Summary: ARGO components related probes.
Version: 0.1.16
Release: 1%{?dist}
License: ASL 2.0
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Group: Network/Monitoring
BuildArch: noarch
Requires: python-requests, argo-ams-library, pyOpenSSL, python-argparse, nagios-plugins-file_age, curl, python-jwt, pytz, python-dateutil

%description
This package includes probes for ARGO components.
Currently it supports the following components:
 - ARGO Consumer log
 - ARGO EGI Connectors
 - ARGO Messaging Service
 - ARGO Web API
 - POEM service

%prep
%setup -q

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}
%{__python} setup.py install --skip-build --root %{buildroot} --record=INSTALLED_FILES
install -d -m 755 %{buildroot}/%{dir}
install -d -m 755 %{buildroot}/%{python_sitelib}/nagios_plugins_argo

%clean
rm -rf %{buildroot}

%files -f INSTALLED_FILES
%defattr(-,root,root,-)
%{python_sitelib}/nagios_plugins_argo
%{dir}


%changelog
* Mon Aug 9 2021 Katarina Zailac <kzailac@srce.hr> - 0.1.16-1%{?dist}
- ARGO-3048 Create probe for certificate validity check for HTCondorCE
- ARGO-3233 Change critical and warning intervals for htcondorce_certvalidity probe
- ARGO-3234 Add checks on CN and CA for htcondorce_certvalidity probe
* Wed Jun 2 2021 Katarina Zailac <kzailac@srce.hr> - 0.1.15-1%{?dist}
- ARGO-3150 Add eduperson_entitlement scope to refresh_token
* Mon Aug 31 2020 Katarina Zailac <kzailac@srce.hr> - 0.1.13-1%{?dist}
- ARGO-2442 Monitor OIDC refresh token expiration
- ARGO-2443 Implement probe for fetching tokens
* Wed Apr 1 2020 Daniel Vrcic <daniel.vrcic@gmail.com>, Angelos Tsalapatis <agelos.tsal@gmail.com> - 0.1.12-1%{?dist}
- ARGO-2014 Update connectors internal tests wrt poem connectors changes
- ARGO-1752 Authn nagios probe
* Thu Nov 8 2018 Daniel Vrcic <daniel.vrcic@gmail.com>, Katarina Zailac <kzailac@srce.hr>, Emir Imamagic <eimamagi@srce.hr>, Angelos Tsalapatis <agelos.tsal@gmail.com> - 0.1.11-1%{?dist}
- ARGO-1369 Check POEM metric configuration API
- ARGO-1271 Publisher probe should display queried time interval on result
- ARGO 1126 Probe for monitoring the compute engine-minor bug fix
- ARGO-1097 Probe for monitoring the compute engine
- ARGO-985 Refine last_update logic of check_nagios sensor
* Tue Mar 27 2018 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.9-1%{?dist}
- added argo-nagios-ams-publisher
* Mon Dec 4 2017 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.8-1%{?dist}
- connectors-probe warning logic revised
- connectors-probe updated global.conf parsing
* Tue Jun 6 2017 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.7-4%{?dist}
- sprint release minor version bump
* Thu May 25 2017 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.7-3%{?dist}
- ams-probe arguments named according to Nagios guidelines
* Thu May 25 2017 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.7-2%{?dist}
- argo-ams-library as dependency
- web_api corrected unused reports function call
* Tue May 16 2017 Hrvoje Sute <sute.hrvoje@gmail.com> - 0.1.7-1%{?dist}
- ARGO-759 Develop a probe that checks the status of AMS
* Wed Apr 26 2017 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.6-4%{?dist}
- converted tab to whitespaces
- check current date for the downtimes state
- vertical line separator for multiple fail msgs
* Wed Apr 26 2017 Hrvoje Sute <sute.hrvoje@gmail.com> - 0.1.6-3%{?dist}
- More descriptive OK status
* Tue Apr 25 2017 Hrvoje Sute <sute.hrvoje@gmail.com> - 0.1.6-2%{?dist}
- Removed debugger lefover module
* Thu Apr 20 2017 Hrvoje Sute <sute.hrvoje@gmail.com> - 0.1.6-1%{?dist}
- ARGO-754 Nagios sensor for connectors component
* Thu Apr 6 2017 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.5-3%{?dist}
- ARGO-773 POEM probe should have argument for client certificate
* Tue Mar 21 2017 Daniel Vrcic <daniel.vrcic@gmail.com>, Themis Zamani <themiszamani@gmail.com> - 0.1.5-2%{?dist}
- POEM probe verify certs in all request calls to remove warning msg
- ARGO-756 [WEB API] - New status check to nagios internal probe
* Thu Mar 9 2017 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.5-1%{?dist}
- ARGO-677 POEM probe should properly check host certificate
* Thu Mar 9 2017 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.4-1%{?dist}
- ARGO-676 Added default --capath to POEM probe
* Thu Mar 9 2017 Emir Imamagic <eimamagi@srce.hr> - 0.1.3-1%{dist}
- Added consumer log probe & deps
* Tue Nov 1 2016 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.2-1%{?dist}
- install as py module to ease the work for upcoming probes
* Mon Sep 5 2016 Daniel Vrcic <daniel.vrcic@gmail.com>, Filip Mendusic <filip.mendjusic@gmail.com> - 0.1.1-1%{?dist}
* POEM probe: certificate and REST API checks
* Thu Aug 25 2016 Themis Zamani <themis@grnet.gr> - 0.1.0-1%{?dist}
- ARGO WEB API probe: Check if api returns results.
