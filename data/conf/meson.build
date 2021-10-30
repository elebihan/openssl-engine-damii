#
# This file is part of openssl-engine-damii
#
# Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
#
# SPDX-License-Identifier: MIT
#

engine_conf = configure_file(input : 'engine.conf.in',
                             output : 'engine.conf',
                             configuration : {
                               'LIBDIR' : libdir
                             },
                             install : true,
                             install_dir : pkgdatadir)
