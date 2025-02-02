#!/usr/bin/env python3
#
# Copyright (C) Matthieu Patou <mat@matws.net>  2010
# Copyright (C) Andrew Bartlett <abartlet@samba.org>  2015
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Change TGT user password
"""

__docformat__ = "restructuredText"


import optparse
import sys
# Allow to run from s4 source directory (without installing samba)
sys.path.insert(0, "bin/python")

import samba.getopt as options
from samba.credentials import DONT_USE_KERBEROS
from samba.auth import system_session
from samba import param
from samba.provision import find_provision_key_parameters
from samba.upgradehelpers import (get_paths,
                                  get_ldbs,
                                 update_krbtgt_account_password)

parser = optparse.OptionParser("chgkrbtgtpass [options]")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)

opts = parser.parse_args()[0]

lp = sambaopts.get_loadparm()
smbconf = lp.configfile
creds = credopts.get_credentials(lp)
creds.set_kerberos_state(DONT_USE_KERBEROS)


paths = get_paths(param, smbconf=smbconf)
session = system_session()

ldbs = get_ldbs(paths, creds, session, lp)
ldbs.startTransactions()

update_krbtgt_account_password(ldbs.sam)
ldbs.groupedCommit()