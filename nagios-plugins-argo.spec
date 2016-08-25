#debuginfo not supported with Go
%global debug_package %{nil}

Name: Nagios-plugins-argo
Summary: ARGO components related probes.
Version: 0.1.1
Release: 1%{?dist}
License: ASL 2.0

Source0: %{name}-%{version}.tgz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Group: Unspecified

%description
This package includes probes for ARGO components. 
Currently it supports the following components:
 - ARGO Web API

%prep
%setup -q

%build

%install
export DONT_STRIP=1
%{__rm} -rf %{buildroot}
install --directory %{buildroot}%{dir}

%changelog
* Thu Mar 24 2016 Themis Zamani <themiszamani@gmail.com> - 0.1.1-1%{?dist}
- ARGO WEB API probe: Check if api returns results.
