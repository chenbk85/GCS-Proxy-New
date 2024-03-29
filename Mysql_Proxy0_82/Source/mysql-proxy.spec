#
# Simple RPM spec file for mysql-proxy
# written by Lenz Grimmer <lenz@mysql.com>
#
%define prefix   /usr

Summary: A Proxy for the MySQL Client/Server protocol
Name: mysql-proxy
Version: 0.8.2.4
Release: 0
License: GPL
Group: Applications/Networking
Source: %{name}-%{version}.tar.gz
URL: http://forge.mysql.com/wiki/MySQL_Proxy
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: mysql-devel glib2-devel libevent
%if 0%{?suse_version} > 1010
%define with_lua 1
%endif
%if 0%{?with_lua}
BuildRequires:  lua-devel >= 5.1
%endif

%description
MySQL Proxy is a simple program that sits between your client and MySQL
server(s) that can monitor, analyze or transform their communication. Its
flexibility allows for unlimited uses; common ones include: load balancing;
failover; query analysis; query filtering and modification; and many more.

%prep
%setup

%build
%configure \
%if 0%{?with_lua}
  --with-lua
%else
  --without-lua
%endif
%{__make}

%install
%makeinstall
# we package them later in the documentation. no reason to have them here
%{__rm} -v %{buildroot}%{_datadir}/*.lua
# we dont need to package the Makefile stuff
%{__rm} -v examples/Makefile*

%clean
%{__rm} -rfv %{buildroot}

%files
%defattr(-,root,root)
%doc AUTHORS COPYING INSTALL NEWS README README.TESTS
%doc examples/
%{_bindir}/%{name}
%{_datadir}/%{name}/
