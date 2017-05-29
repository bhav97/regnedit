#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" consumes dumps from the MCT android app, replaces registration number
		exit codes:
			1 - Invalid usage
			2 - Invalid Registration number
"""

import sys
import os

def get_sector_map_from_dump(dump):
	""" converts dump data into a sector map
			arguments:
				dump (str) : data read from dumpfile
			returns:
				data (dict) : a map of sector and data
	"""
	print("[+] Converting dump into a Sector Map")
	data = dump.split("+Sector: ")
	data[-1] = data[-1] + '\n'
	data = [d.split("\n") for d in data]
	# remove unecessary data
	print("[-] Removing unecessary data")
	del data[0]
	for blk in data:
		# last item is empty block
		del blk[-1]

	data = {da[0]: [d for d in da] for da in data}
	# remove sector number from block list and separate keys
	print("[-] Generating Key Tuple for each sector")
	for idx  in data:
		del data[idx][0]
		data[idx][-1] = get_keys_from_block(data[idx][-1], idx)
	data = {int(k) : v for k, v in data.items()}
	return data

def get_keys_from_block(block, ctx):
	""" splits block into KEY A, KEY B, ACCESS BITS
		KEY A: first 6 bytes
		KEY B: last 6 bytes
		ACCESS BITS: center 4 bytes
		arguments:
			block (str) : block data
		returns:
			tuple
				'-> key A (str)
				'-> access bits (str)
				'-> key B (str)
	"""
	if block[:12] == '-'*12:
		print("[*] Missing Key A at Sector {}".format(ctx))
	elif block[12:20] == '-'*8:
		print("[*] Missing Access Bits at Sector {}".format(ctx))
	elif block[20:] == '-'*12:
		print("[*] Missing Key B at Sector {}".format(ctx))
	return block[:12], block[12:20], block[20:]

def calculate_offset(number, sector, sector_idx):
	""" calculate offset of the number in sector
	"""
	# print("".join(sector))
	print("[+] Calculating offset in Sector {}".format(sector_idx))
	sector_data = ""
	for sctr in range(0, len(sector)-1):
		sector_data += sector[sctr]
	if check_zero(sector_data, 0, len(sector_data)):
		print("[*] Sector {} is zeroes".format(sector_idx))
	try:
		return sector_data.index(number)
	except ValueError:
		print("[!] Could not determine offset at Sector {}".format(sector_idx))
		sys.exit(3)

def check_zero(string, start, end):
	""" checks if part of a string is zeroes
			arguments:
				string (str) : str
				start (int) : start index
				end (int): end index
			returns:
				(bool) whether string is zeros
	"""
	return string[start:end] == int(end - start) * str(0x00)

def sthexs(number):
	""" converts registration number into hex string
			arguments:
				reg (str) : registration number
			returns:
				(str) hex encoded registration number
	"""
	try:
		return "".join("{:02x}".format(ord(c)) for c in number)
	except TypeError:
		print("[!] Error converting \'{}\' to hex".format(number))
		sys.exit(1)

def modify_sector_map(sector_map, number, offset, sector):
	""" replaces 9 bytes with number in sector map at sector with offset
		arguments:
			sector_map:
			number:
			offset:
			sector:
			should it return?is there a point now? is there?
		returns:
			data:
	"""
	print("[+] Modifying Sector Map")
	sector_data = list(sector_map[sector][0] + sector_map[sector][1] + sector_map[sector][2])
	if offset + len(number) > len(sector_data):
		print("[!] Offset \'{}\' and number size \'{}\' is larger than sector \'{}\'\
			".format(offset, len(number), len(sector_data)))
		sys.exit(4)
	for idx in range(0, len(number)):
		sector_data[idx + offset] = number[idx]
	for idx in range(0, len(sector_data), 32):
		sector_map[sector][int(idx/32)] = "".join(sector_data[idx:idx+32])

def sector_map_to_data(sector_map):
	""" convert sector map into writable data
	"""
	print("[+] Converting sector map to writable data format")
	wrdat = ""
	for idx, data in sector_map.items():
		data[-1] = "".join(data[-1])
		wrdat += "+Sector: " + str(idx) + "\n" + "\n".join(data) + "\n"
	wrdat = wrdat[:-1]
	return wrdat

def main(old_reg, new_reg, dumppath, sector, offset):
	""" edits dumpfile
			arguments:
				old_reg (str): registration number in the card dump
					used to calculate offset to embed registration number at
				new_reg (str): registration number to embed in the dump
				dumpfile (str): path to dumpfile
				sector (int): sector number to edit
					if None, all sctors are
				offset (int): offset of registration number in the sector
					if N???
	"""
	if len(old_reg) != 9 or len(new_reg) != 9:
		print("[!] Registration number looks invalid")
		sys.exit(1)
	if sector is not None and sector < 0:
		print("[!] Invalid Sector: \'{}\'".format(sector))
		sys.exit(1)
	if offset is not None and offset < 0:
		print("[!] Invalid offset: \'{}\'".format(offset))
	# String to hex string
	old_reg = sthexs(old_reg)
	new_reg = sthexs(new_reg)
	# read dump
	try:
		with open(dumppath, "r", encoding="utf-8") as dumpfile:
			# convert into a sector map
			sector_map = get_sector_map_from_dump(dumpfile.read())
	except IOError as ose:
		print("[!] Error opening dumpfile: {}".format(ose.strerror))
		sys.exit(3)
	if sector is None:
		sector = 0
	if sector not in sector_map:
		print("[!] Requested sector {} not found in dump".format(sector))
		sys.exit(1)
	print("[-] Sector set {}".format(sector))
	if offset is None:
		offset = calculate_offset(old_reg, sector_map[sector], sector)
	print("[-] Offset set {}".format(offset))
	modify_sector_map(sector_map, new_reg, offset, sector)
	print("[-] Creating new dump: \'{}\'".format(dumppath + "_new"))
	if os.path.isfile(dumppath + "_new"):
		print("[*] Warning existing file will be overwritten")
	try:
		with open(dumppath + "_new", "w") as outfile:
			outfile.seek(0x00)
			outfile.write(sector_map_to_data(sector_map))
			outfile.truncate()
	except IOError as ioe:
		print("[!] Error creating edited dump: {}".format(ioe.strerror))
		sys.exit(1)
	print("[!] Created new dump at \'{}\'".format(dumppath + "_new"))

def usage():
	""" print usage information
	"""
	print("Usage: regnedit [OPTION...] <dump> <old registration number> <new registration number>")
	print("\nHelp Options:\n\t-h, --help\t\tShow this message")
	print("\nApplication Options:")
	print("\t-o, --offset\t\tSet offset of location to embed in sector (auto calculated by default)")
	print("\t-s, --sector\t\tSet sector (defaults to zero)")

if __name__ == '__main__' or 1:
	OREG = None
	NREG = None
	DUMP = None
	SECTOR = None
	OFFSET = None
	ARGC = 4
	for i in range(1, len(sys.argv)):
		if sys.argv[i] == "-h" or sys.argv[i] == "--help":
			usage()
			sys.exit(0)
		elif (sys.argv[i].split("=")[0] == "-o" or sys.argv[i].split("=")[0] == "--offset") \
		and len(sys.argv[i].split("=")) == 2:
			OFFSET = sys.argv[i].split("=")
			try:
				OFFSET = int(OFFSET[1])
			except ValueError:
				print("[!] Cannot parse integer value \'{}\' for \'{}\'".format(OFFSET[1], OFFSET[0]))
				usage()
				sys.exit(1)
		elif (sys.argv[i].split("=")[0] == "-s" or sys.argv[i].split("=")[0] == "--sector") \
		and len(sys.argv[i].split("=")) == 2:
			SECTOR = sys.argv[i].split("=")
			try:
				SECTOR = int(SECTOR[1])
			except ValueError:
				print("[!] Cannot parse integer value \'{}\' for \'{}\'".format(SECTOR[1], SECTOR[0]))
				usage()
				sys.exit(1)
		elif sys.argv[i] == "-a" or sys.argv[i] == "--allsec":
			ALLSEC = True
		elif not DUMP:
			DUMP = sys.argv[i]
		elif not OREG:
			OREG = sys.argv[i]
		elif not NREG:
			NREG = sys.argv[i]
	ARGC += 1 if SECTOR is not None else 0
	ARGC += 1 if OFFSET is not None else 0
	if len(sys.argv) == ARGC:
		main(OREG, NREG, DUMP, SECTOR, OFFSET)
	else:
		usage()
		sys.exit(1)
