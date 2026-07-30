# -*- rpm-spec -*-
%global _enable_debug_packages 0
%global _debugsource_packages 1
%global _build_id_links none

Name:           cdf-crypto
Version:        1.0.0
Release:        1
Summary:        Confidential Data defensive Framework
Summary(zh_CN): 敏感数据保护框架（CDF）
License:        MulanPSL-2.0
URL:            https://atomgit.com/openeuler/cdf-crypto.git
Source0:        %{name}-%{version}.tar.gz
Source1:        openssl-3.0.9.tar.gz
Source2:        blake3-1.8.5.tar.gz
# Add future source fixes as Patch0, Patch1, ...; %%autosetup applies them.
# Patch0:        cdf-crypto-example.patch

BuildRequires:  cmake >= 3.14.1
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  libboundscheck
BuildRequires:  rapidjson-devel
BuildRequires:  krb5-devel
BuildRequires:  /usr/bin/perl

%global cdf_build_dir %{_builddir}/%{name}-%{version}/rpm-build
%global cdf_stage_dir %{_builddir}/%{name}-%{version}/rpm-install

%description
cdf-crypto (Confidential Data defensive Framework) provides cryptographic
algorithms and key security functions.

# Explicitly request both debuginfo and debugsource subpackages. Disabling the
# distro's automatic insertion above avoids duplicate subpackage definitions.
%debug_package

%prep
%autosetup -n %{name}-%{version} -p1

%build
%set_build_flags
cmake -S . -B "%{cdf_build_dir}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=%{_prefix} \
    -DCMAKE_INSTALL_BINDIR=bin \
    -DCMAKE_INSTALL_INCLUDEDIR=include \
    -DCMAKE_INSTALL_LIBDIR=%{_lib} \
    -DBUILD_TEST=OFF \
    -DBUILD_COVERAGE=OFF \
    -DBUILD_ASAN=OFF \
    -DBUILD_FUZZ=OFF \
    -DENABLE_SHARED=ON \
    -DENABLE_DOWNLOAD_DEPENDENCY=OFF \
    -DOPENSSL_SOURCE_ARCHIVE=%{SOURCE1} \
    -DENABLE_BLAKE3=ON \
    -DBLAKE3_SOURCE_ARCHIVE=%{SOURCE2} \
    -DENABLE_MODULES=ALL
cmake --build "%{cdf_build_dir}" --parallel %{?_smp_build_ncpus}

%install
rm -rf %{buildroot} "%{cdf_stage_dir}"
DESTDIR="%{cdf_stage_dir}" cmake --install "%{cdf_build_dir}"

mkdir -p %{buildroot}%{_includedir}/cdf
mkdir -p %{buildroot}%{_libdir}/cdf
mkdir -p %{buildroot}%{_bindir}/cdf/config
mkdir -p %{buildroot}%{_bindir}/cdf/bin

if [ -d "%{cdf_stage_dir}%{_bindir}" ]; then
    cp -a "%{cdf_stage_dir}%{_bindir}/." %{buildroot}%{_bindir}/cdf/bin/
fi
if [ -d "%{cdf_stage_dir}%{_prefix}/config" ]; then
    cp -a "%{cdf_stage_dir}%{_prefix}/config/." %{buildroot}%{_bindir}/cdf/config/
fi
if [ -d "%{cdf_stage_dir}%{_includedir}/cdf" ]; then
    cp -a "%{cdf_stage_dir}%{_includedir}/cdf/." %{buildroot}%{_includedir}/cdf/
fi
if [ -d "%{cdf_stage_dir}%{_libdir}" ]; then
    cp -a "%{cdf_stage_dir}%{_libdir}/." %{buildroot}%{_libdir}/cdf/
fi

# RPM post-processing extracts debug data and strips ELF files in buildroot;
# both operations require owner-write. The manifest resets final permissions.
find %{buildroot}%{_bindir}/cdf/bin \
     %{buildroot}%{_libdir}/cdf -type f -exec chmod u+w {} \;

# Match the file ownership and permissions of the build.sh/CPack RPM exactly.
manifest=%{_builddir}/cdf-crypto.files
for owned_root in \
    %{buildroot}%{_bindir}/cdf \
    %{buildroot}%{_includedir}/cdf \
    %{buildroot}%{_libdir}/cdf; do
    find "${owned_root}" -type d -print
done | sed -e 's#^%{buildroot}##' \
           -e 's#^#%%dir %%attr(750,root,root) #' > "${manifest}"
find %{buildroot}%{_bindir}/cdf/config -type f -print | \
    sed -e 's#^%{buildroot}##' \
        -e 's#^#%%config(noreplace) %%attr(640,root,root) #' >> "${manifest}"
find %{buildroot}%{_bindir}/cdf/bin -type f -print | \
    sed -e 's#^%{buildroot}##' \
        -e 's#^#%%attr(750,root,root) #' >> "${manifest}"
find %{buildroot}%{_includedir}/cdf -type f -print | \
    sed -e 's#^%{buildroot}##' \
        -e 's#^#%%attr(440,root,root) #' >> "${manifest}"
find %{buildroot}%{_libdir}/cdf \( -type f -o -type l \) -print | \
    sed -e 's#^%{buildroot}##' \
        -e 's#^#%%attr(550,root,root) #' >> "${manifest}"

%files -f %{_builddir}/cdf-crypto.files
%defattr(750,root,root,750)

%clean
rm -rf %{buildroot} "%{cdf_stage_dir}"

%changelog
