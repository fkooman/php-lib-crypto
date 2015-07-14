%global composer_vendor  fkooman
%global composer_project crypto

%global github_owner     fkooman
%global github_name      php-lib-crypto

Name:       php-%{composer_vendor}-%{composer_project}
Version:    1.0.0
Release:    1%{?dist}
Summary:    A simple encryption and decryption library

Group:      System Environment/Libraries
License:    ASL 2.0
URL:        https://github.com/%{github_owner}/%{github_name}
Source0:    https://github.com/%{github_owner}/%{github_name}/archive/%{version}.tar.gz
BuildArch:  noarch

Provides:   php-composer(%{composer_vendor}/%{composer_project}) = %{version}

Requires:   php(language) >= 5.4
Requires:   php-hash
Requires:   php-openssl
Requires:   php-spl
Requires:   php-standard

Requires:   php-composer(fkooman/base64) >= 1.0
Requires:   php-composer(fkooman/base64) < 2.0
Requires:   php-composer(fkooman/json) >= 1.0
Requires:   php-composer(fkooman/json) < 2.0

%description
A simple symmetric encryption and decryption library using secure hashes with 
zero configuration.

%prep
%setup -qn %{github_name}-%{version}

%build

%install
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/php
cp -pr src/* ${RPM_BUILD_ROOT}%{_datadir}/php

%files
%defattr(-,root,root,-)
%dir %{_datadir}/php/%{composer_vendor}/Crypto
%{_datadir}/php/%{composer_vendor}/Crypto/*
%doc README.md CHANGES.md composer.json
%license COPYING

%changelog
* Mon Jul 13 2015 François Kooman <fkooman@tuxed.net> - 1.0.0-1
- initial package

