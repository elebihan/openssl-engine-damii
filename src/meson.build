#
# This file is part of openssl-engine-damii
#
# Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
#
# SPDX-License-Identifier: MIT
#

openssl_engine_damii_sources = [
  'context.h',
  'context.c',
  'engine.h',
  'engine.c',
  'key.h',
  'keys.h',
]

deps = [ openssl, crypto, tomcrypt, tommath]

openssl_engine_damii = shared_library('damii'.format(apiversion),
                                      openssl_engine_damii_sources,
                                      name_prefix : '',
                                      c_args : ['-DUSE_LTM', '-DLTM_DESC'],
                                      dependencies : deps,
                                      soversion : soversion,
                                      version : libversion,
                                      install: true,
                                      install_dir : libdir)
