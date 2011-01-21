#!/bin/bash
# vi: set ts=4 sw=4
# Hallock
# pam_gmirror module
#
# This script will create global groups locally.
#
# $Id$
# Copyright (C) 2008-2011, vitki.net
#

force=1

add_grp()
{
	gid=$1
	name=$2
	comment=$3
	[ $force != 0 ] && groupdel $name >/dev/null 2>&1
	groupadd -g $gid $name
}

add_grp 1201 hw_use_drive   "mount, read and write external pluggable disks, removable data volumes, cd-roms or dvd-roms, usb cameras and players with storage access"
add_grp 1202 hw_read_drive  "mount read-only external pluggable disks or removable data volumes, cd-roms or dvd-roms, usb cameras and players with storage access"
add_grp 1203 hw_burn_disc   "burn appendable, blank and rewritable cd-roms or dvd-roms"
add_grp 1204 hw_play_disc   "play cdda audio, vcd video or dvd video from cd-roms or dvd-roms"
add_grp 1205 hw_write_hdd   "mount internal (ide or scsi) disk partitions for reading and writing"
add_grp 1206 hw_read_hdd    "mount internal (ide or scsi) disk partitions for reading only"
add_grp 1207 hw_use_pda     "synchronize data with pluggable PDA or Pocket PC"
add_grp 1208 hw_use_player  "upload/download music from pluggable portable audio/video players"
add_grp 1209 hw_use_printer "plug and use printers"
add_grp 1210 hw_use_ports   "connect external devices to serial and parallel ports"
add_grp 1211 hw_use_input   "plug and use usb keyboards, mice, tablets, scanners, webcams or microphones"
add_grp 1212 hw_use_other   "plug and use pluggable devices that are not recongnized"

