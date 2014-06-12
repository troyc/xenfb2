#
# Copyright (c) 2011 Citrix Systems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

ifneq ($(KERNELRELEASE),)
include Kbuild
else

KERNELDIR ?= /lib/modules/`uname -r`/build
PREFIX ?= /usr

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@

modules:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean
	rm -f Makefile.xen

modules_install:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules_install

install:
	install -m 0755 -d $(PREFIX)/include
	install -m 0644 fb2if.h $(PREFIX)/include


endif
