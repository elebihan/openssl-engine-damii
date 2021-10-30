#
# This file is part of openssl-engine-damii
#
# Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
#
# SPDX-License-Identifier: MIT
#

project('openssl-engine-damii', 'c',
        version : '0.1.1',
        license : '',
        default_options : [
          'c_std=c99',
          'prefix=/usr',
        ],
        meson_version : '>= 0.58')

openssl_engine_damii_version = meson.project_version()
ver_arr = openssl_engine_damii_version.split('.')

openssl_engine_damii_major_version = ver_arr[0].to_int()
openssl_engine_damii_minor_version = ver_arr[1].to_int()
openssl_engine_damii_micro_version = ver_arr[1].to_int()

apiversion = '0.0'
soversion = 0
libversion = '@0@.@1@.0'.format(soversion,
                                openssl_engine_damii_minor_version * 100 +
                                openssl_engine_damii_micro_version)

prefixdir = get_option('prefix')
libdir = join_paths(prefixdir, get_option('libdir'))
sysconfdir = join_paths(prefixdir, get_option('sysconfdir'))
datadir = join_paths(prefixdir, get_option('datadir'))
pkgdatadir = join_paths(datadir, meson.project_name())

pkg_defs = [
  ['PACKAGE_NAME', meson.project_name()],
  ['PACKAGE_STRING', '@0@ @1@'.format(meson.project_name(),
                                      meson.project_version())],
  ['PACKAGE_VERSION', meson.project_version()],
]

conf = configuration_data()

foreach def : pkg_defs
  conf.set_quoted(def[0], def[1])
endforeach

config_h = configure_file(output : 'config.h',
                          configuration : conf)

openssl = dependency('openssl', required : true, version : '>=1.1')
crypto = dependency('libcrypto', required : true, version : '>=1.1')
tomcrypt = dependency('libtomcrypt', required : true, version : '>=1.18')

subdir('data')
subdir('src')

enable_tests = get_option('tests')
if enable_tests
  check = dependency('check', required : true, version : '>=0.12')
  subdir('tests')
endif

status = [
  '@0@ @1@'.format(meson.project_name(), meson.project_version()),

  'prefix:         @0@'.format(prefixdir),
  'libdir:         @0@'.format(libdir),
]

message('\n         '.join(status))
