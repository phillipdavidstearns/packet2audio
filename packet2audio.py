#!/usr/bin/env python3
"""

packet2audio

example usage: ./packet2audio.py -i wlan0

A minimal script to hoover up network traffic and spit it out the audio interface.
Non-blocking by design. Why would you ever want any of these things to block? LMK!
Tested and working on Raspberry Pi v3 B+ (Raspbian Stretch), Debian 9.9, Kali Linux
Might work on Debian VMs (untested)
Compatible with python3
Not compatible with MacOSX (tested).
Windows compatibility not tested.
Requirements: pyaudio, asyncio

install pyaudio on Debian systems using:

$ sudo apt-get update && sudo apt-get install python3-pyaudio -y

install asyncio on Debian systems using:

$ sudo apt-get install python3-pip
$ pip3 install asyncio

by Phillip David Stearns 2019

Code cobbled together from examples at:

http://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html
https://people.csail.mit.edu/hubert/pyaudio/#wire-callback-example
https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python#1112350

A nice link illuminating protocol codes in linux
https://github.com/torvalds/linux/blob/ead751507de86d90fa250431e9990a8b881f713c/include/uapi/linux/if_ether.h
"""

# modules
import os
import sys
import argparse
from signal import *
import socket
import pyaudio
import re
import asyncio

# create sockets
def create_sockets(interfaces):
	sockets = []
	for n in range(CHANNELS):
		s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
		try:
			s.bind((interfaces[n], 0))
		except:
			print("Failed to bind to interface: " + interfaces[n])
			sys.exit(1)
		s.setblocking(False)
		sockets.append(s)
	return sockets

# create pyaudio stream(s)
def init_pyaudio_stream(PyAudio, width, channels, rate, frames_per_buffer):
	return PyAudio.open(format=pyaudio.get_format_from_width(width),
			    channels=channels,
	 		    rate=rate,
	 		    frames_per_buffer=frames_per_buffer,
	 		    input=False,
	 		    output_device_index=0,
	 		    output=True,
			    stream_callback=audify_data_callback)

def audify_data_callback(in_data, frame_count, time_info, status):
	return(bytes(extract_frames(packets, frame_count)), pyaudio.paContinue)

# does what it says on the tin
def extract_frames(buffers, frames):
	chunk = bytearray()
	string = ""
	# assemble frames into chunk
	for i in range(frames):
		for n in range(CHANNELS):
			try:
				frame = buffers[n][i]
			except:
				frame = 127
			chunk.append(frame)
			if PRINT:
				try:
					char=chr(frame)
				except:
					char=''
				if COLOR:
					color = (int(frame)+SHIFT+256)%256
					string += '\x1b[48;5;%sm%s' % (color, char)
				else:
					string += char
	for n in range(CHANNELS):
		buffers[n] = buffers[n][frames:]
	if PRINT: 
		if COLOR: string+'\x1b[0m'
		print(string, end='')
	return chunk

async def read_sockets(buffers):
	for n in range(len(sockets)):
		# if len(buffers[n]) < 65536: # had this here in case they got too big?
		try:
			data = await asyncio.get_running_loop().run_in_executor(None, lambda: sockets[n].recv(65536))
			buffers[n] += data
		except Exception as e:
			pass

def shutdown(PyAudio, socket_list):
	if PRINT and COLOR:
		print('\x1b[0m',end='')
	# bring down the pyaudio stream
	print('Stopping audio stream...')
	try:
		PyAudio.terminate()
	except:
		print("Failed to terminate PyAudio instance.")
	# close the sockets
	for n in range(len(socket_list)):
		print('Closing socket '+str(interfaces[n])+'...')
		try:
			socket_list[n].close()
		except:
			print("Error closing socket.")
	try:
		print('Shutting down asyncio event loop.')
		asyncio.get_running_loop().stop()
	except:
		print("Couldn't stop asyncio event loop.")

	print('Peace out!')
	sys.exit(0)

# catch control+c
def SIGINT_handler(sig, frame):
	if PRINT and COLOR:
		print('\x1b[0m',end='')
	print('\nSIGINT received!')
	shutdown(PA, sockets)

# catch termination signals from the system
def SIGTERM_handler(sig, frame):
	if PRINT and COLOR:
		print('\x1b[0m',end='')
	print('\nSIGTERM received!')
	shutdown(PA, sockets)

async def main():
	# interrupt and terminate signal handling
	signal(SIGINT, SIGINT_handler)
	signal(SIGTERM, SIGTERM_handler)

	print("Sniffing packets...")
	while True:
		await asyncio.sleep(2/CHUNK)
		await read_sockets(packets)

if __name__ == "__main__":
	try:
		ap = argparse.ArgumentParser()
		ap.add_argument("-i", "--interface", required=True, help="[if0[,if1]]")
		ap.add_argument("-c", "--chunk-size", type=int, default=4096, required=False, help="chunk size in frames")
		ap.add_argument("-r", "--sample-rate", type=int, default=44100, required=False, help="frames per second")
		ap.add_argument("-w", "--width", type=int, default=1, required=False, help="bytes per sample")
		ap.add_argument("-p", "--print-packet", action='store_true', default=False, required=False, help="print packet to console")
		ap.add_argument("-C", "--print-color", action='store_true', default=False, required=False, help="colorize console output")
		ap.add_argument("-s", "--color-shift", type=int, default=-127, required=False, help="color shift for colorized printing")
		
		args = ap.parse_args()

		# check to see if user is root
		if os.getuid() != 0:
			print("Must be run as root!")
			exit(1)

		interfaces = []
		packets = []

		ifs = re.split(r'[:;,\.\-_\+|]', args.interface)
		CHANNELS = len(ifs)

		for i in range(len(ifs)) :
			interfaces.append(ifs[i])
			packets.append(bytearray())

		CHUNK = args.chunk_size
		RATE = args.sample_rate
		WIDTH = args.width
		PRINT = args.print_packet
		COLOR = args.print_color
		SHIFT =  min(256,max(-256,args.color_shift))

		print("INTERFACES: ", end=' ')
		print(interfaces)
		print("CHANNELS: " + str(CHANNELS))
		print("CHUNK SIZE: " + str(CHUNK))
		print("SAMPLE RATE: " + str(RATE))
		print("BYTES PER SAMPLE: " + str(WIDTH))

		try:
			sockets = create_sockets(interfaces)
		except:
			print("Unable to create sockets.")
			sys.exit(1)

		# initialize pyaudio stream
		try:
			PA = pyaudio.PyAudio()
			stream = init_pyaudio_stream(PA,WIDTH,CHANNELS,RATE,CHUNK)
		except:
			print("Unable to create audio stream.")
			sys.exit(1)

		# start the stream
		try:
			print("Starting audio stream...")
			stream.start_stream()
			if stream.is_active():
				print("Audio stream is active.")
		except:
			print("Unable to start audio stream.")

		# run the main loop
		asyncio.run(main())

	except Exception as e:
		print('Ooops! Exception caught:',e)
