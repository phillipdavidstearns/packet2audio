#!/usr/bin/env python3
"""

packet2audio

example usage: ./packet2audio.py -i wlan0

A minimal script to hoover up network traffic and spit it out the audio interface.
Tested and working on Raspberry Pi v3 B+ (Raspbian Stretch), Debian 9.9, Kali Linux
Might work on Debian VMs (untested)
Compatible with python3
Not compatible with MacOSX (tested).
Windows compatibility not tested.
Requirements: pyaudio

install pyaudio on Debian systems using:

$ sudo apt-get update && sudo apt-get install python3-pyaudio

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
import time
import select
import re

ap = argparse.ArgumentParser()
ap.add_argument("-a", "--audio-blocking", action='store_true', default=False, required=False, help="non-blocking by default")
ap.add_argument("-s", "--socket-blocking", action='store_true', default=False, required=False, help="non-blocking by default")
ap.add_argument("-i", "--interface", required=True, help="[if0[,if1]]")
ap.add_argument("-c", "--chunk-size", type=int, default=2048, required=False, help="chunk size in frames")
ap.add_argument("-r", "--sample-rate", type=int, default=44100, required=False, help="frames per second")
ap.add_argument("-w", "--width", type=int, default=1, required=False, help="bytes per sample")
ap.add_argument("-t", "--timeout", type=float, default=0.0, required=False, help="socket timeout in seconds")
ap.add_argument("-p", "--print-packet", action='store_true', default=False, required=False, help="print packet to console")
args = ap.parse_args()

# check to see if user is root
if os.getuid() != 0:
	print("Must be run as root!")
	exit(1)

interfaces = []
packets = []

ifs = re.split("[:;,.\-_\+]", args.interface)
CHANNELS = len(ifs)

for i in range(len(ifs)) :
	interfaces.append(ifs[i])
	packets.append(bytearray())

AUDIO_BLOCKING = args.audio_blocking
SOCKET_BLOCKING = args.socket_blocking
CHUNK = args.chunk_size
RATE = args.sample_rate
WIDTH = args.width
if args.timeout > 0.0:
	TIMEOUT = args.timeout
else:
	TIMEOUT = 1 / CHUNK
PRINT = args.print_packet

print("AUDIO_BLOCKING: " + str(AUDIO_BLOCKING))
print("SOCKET_BLOCKING: " + str(SOCKET_BLOCKING))
print("INTERFACES: ", end=' ')
print(interfaces)
print("CHANNELS: " + str(CHANNELS))
print("CHUNK SIZE: " + str(CHUNK))
print("SAMPLE RATE: " + str(RATE))
print("BYTES PER SAMPLE: " + str(WIDTH))
print("SOCKET TIMEOUT: " + str(TIMEOUT))

PA = pyaudio.PyAudio()

# create sockets
sockets = []

for n in range(CHANNELS):
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
	try:
		s.bind((interfaces[n], 0))
	except:
		print("Failed to bind to interface: " + interfaces[n])
		sys.exit(1)
	s.setblocking(SOCKET_BLOCKING)
	sockets.append(s)

# create pyaudio stream(s)
def init_pyaudio_stream(PyAudio=PA, width=WIDTH, channels=CHANNELS, rate=RATE, frames_per_buffer=CHUNK, input=False, output=True, blocking=AUDIO_BLOCKING):
	if blocking:
		return PyAudio.open(format=pyaudio.get_format_from_width(width),
				    channels=channels,
				    rate=rate,
				    frames_per_buffer=frames_per_buffer,
				    input=input,
				    output=output)
	else:
		return PyAudio.open(format=pyaudio.get_format_from_width(width),
				    channels=channels,
		 		    rate=rate,
		 		    frames_per_buffer=frames_per_buffer,
		 		    input=input,
		 		    output=output,
				    stream_callback=audify_data_callback)

def audify_data_callback(in_data, frame_count, time_info, status):
	return(bytes(extract_frames(packets, frame_count)), pyaudio.paContinue)

def audify_data(buffers, pa_stream):
	pa_stream.write(bytes(extract_frames(buffers, pa_stream.get_write_available())))

# does what it says on the tin
def extract_frames(buffers, frames):
	chunk = bytearray()
	# assemble frames into chunk
	for i in range(frames):
		for n in range(CHANNELS):
			try:
				frame = buffers[n][i]
				if PRINT: print(chr(frame),end='')
			except:
				frame = 127
			chunk.append(frame)
	for n in range(CHANNELS):
		buffers[n] = buffers[n][frames:]
	return chunk

def read_sockets(buffers):
	if SOCKET_BLOCKING:
		readable,_,_ = select.select(sockets, [], [], TIMEOUT)
		for socket in readable:
			try:
				data, interface = socket.recvfrom(65536)
				if data:
					for n in range(CHANNELS):
						if interface[0]==interfaces[n]:
							buffers[n] += data
			except:
				pass
	else:
		for n in range(len(sockets)):
			if len(buffers[n]) < 65536:
				try:
					data = sockets[n].recv(65536)
					if data:
						buffers[n] += data
				except:
					pass

def shutdown(PyAudio, socket_list):
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
	print('Peace out!')
	sys.exit(0)

# catch control+c
def SIGINT_handler(sig, frame):
	print('\nSIGINT received!')
	shutdown(PA, sockets)

# catch termination signals from the system
def SIGTERM_handler(sig, frame):
	print('\nSIGTERM received!')
	shutdown(PA, sockets)

def main():
	# interrupt and terminate signal handling
	signal(SIGINT, SIGINT_handler)
	signal(SIGTERM, SIGTERM_handler)

	# initialize pyaudio stream
	try:
		stream = init_pyaudio_stream()
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

	print("Sniffing packets...")

	while True:
		#give the processor a rest
		time.sleep(1/CHUNK)
		read_sockets(packets)
		if AUDIO_BLOCKING: audify_data(packets, stream)

if __name__ == "__main__":
	main()
