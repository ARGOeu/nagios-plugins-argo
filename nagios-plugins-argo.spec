#debuginfo not supported with Go
%global debug_package %{nil}

Name: Nagios-plugins-argo
Summary: ARGO components related probes.
Version: 0.1.0
Release: 1%{?dist}
License: ASL 2.0
Source0: %{name}-%{version}.tgz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Group: Network/Monitoring
BuildArch: noarch

%description
This package includes probes for ARGO components. 
Currently it supports the following components:
 - ARGO Web API

%prep
%setup -q

%build

%install
rm -rf $RPM_BUILD_ROOT
install --directory ${RPM_BUILD_ROOT}%{dir}
install --mode 755 src/*  ${RPM_BUILD_ROOT}%{dir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{dir}


%changelog
* Thu Mar 24 2016 Themis Zamani <themiszamani@gmail.com> - 0.1.1-1%{?dist}
- ARGO WEB API probe: Check if api returns results.
