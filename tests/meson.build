#
# This file is part of openssl-engine-damii
#
# Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
#
# SPDX-License-Identifier: MIT
#

tests_conf = configure_file(input: 'tests.conf.in',
                            output : 'tests.conf',
                            configuration : {
                              'LIBDIR' : meson.global_build_root() / 'src'
                            })
test_engine = executable('test-engine', 'test-engine.c',
                         dependencies : [openssl, check],
                         include_directories: include_directories('../src'))

test('Test engine', test_engine, args : [
  tests_conf,
  meson.global_source_root() / 'tests' / 'data'
])
