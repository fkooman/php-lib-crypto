%global composer_vendor  fkooman
%global composer_project crypto

%global github_owner     fkooman
%global github_name      php-lib-crypto

Name:       php-%{composer_vendor}-%{composer_project}
Version:    1.0.0
Release:    2%{?dist}
Summary:    A simple encryption and decryption library

Group:      System Environment/Libraries
License:    ASL 2.0
URL:        https://github.com/%{github_owner}/%{github_name}
Source0:    https://github.com/%{github_owner}/%{github_name}/archive/%{version}.tar.gz
Source1:    %{name}-autoload.php

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
Requires:   php-composer(symfony/class-loader)

BuildRequires:  php-composer(symfony/class-loader)
BuildRequires:  %{_bindir}/phpunit
BuildRequires:  %{_bindir}/phpab
BuildRequires:  php-composer(fkooman/base64) >= 1.0
BuildRequires:  php-composer(fkooman/base64) < 2.0
BuildRequires:  php-composer(fkooman/json) >= 1.0
BuildRequires:  php-composer(fkooman/json) < 2.0

%description
A simple symmetric encryption and decryption library using secure hashes with 
zero configuration.

%prep
%setup -qn %{github_name}-%{version}
cp %{SOURCE1} src/%{composer_vendor}/Crypto/autoload.php

%build

%install
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/php
cp -pr src/* ${RPM_BUILD_ROOT}%{_datadir}/php

%check
%{_bindir}/phpab --output tests/bootstrap.php tests
echo 'require "%{buildroot}%{_datadir}/php/%{composer_vendor}/Crypto/autoload.php";' >> tests/bootstrap.php
%{_bindir}/phpunit \
    --bootstrap tests/bootstrap.php

%files
%defattr(-,root,root,-)
%dir %{_datadir}/php/%{composer_vendor}/Crypto
%{_datadir}/php/%{composer_vendor}/Crypto/*
%doc README.md CHANGES.md composer.json example.php
%license COPYING

%changelog
* Fri Sep 04 2015 François Kooman <fkooman@tuxed.net> - 1.0.0-2
- add autoloader
- run tests during build

* Mon Jul 13 2015 François Kooman <fkooman@tuxed.net> - 1.0.0-1
- initial package
