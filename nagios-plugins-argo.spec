# sitelib
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%define dir %{_libdir}/nagios/plugins/argo

Name: nagios-plugins-argo
Summary: ARGO components related probes.
Version: 0.1.2
Release: 1%{?dist}
License: ASL 2.0
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Group: Network/Monitoring
BuildArch: noarch
Requires: python-requests, pyOpenSSL, python-argparse

%description
This package includes probes for ARGO components. 
Currently it supports the following components:
 - ARGO Web API
 - POEM

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
* Tue Nov 1 2016 Daniel Vrcic <daniel.vrcic@gmail.com> - 0.1.2-1%{?dist}
- install as py module to ease the work for upcoming probes
* Mon Sep 5 2016 Daniel Vrcic <daniel.vrcic@gmail.com>, Filip Mendusic <filip.mendjusic@gmail.com> - 0.1.1-1%{?dist}
* POEM probe: certificate and REST API checks
* Thu Aug 25 2016 Themis Zamani <themis@grnet.gr> - 0.1.0-1%{?dist}
- ARGO WEB API probe: Check if api returns results.
