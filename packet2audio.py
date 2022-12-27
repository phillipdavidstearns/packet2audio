#!/usr/bin/env python3
"""

packet2audio

example usage: ./packet2audio.py -i wlan0

A minimal script to hoover up network traffic and spit it out the audio interface.
Non-blocking by design. Why would you ever want any of these things to block? LMK!
Tested and working on Raspberry Pi v3 B+ (Raspbian Stretch), Debian 9.9, Kali Linux
Might work on Debian VMs (untested)
Compatible with python3
Not compatible with MacOSX (tested).x
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
from threading import Thread
from time import sleep, time

class Listener(Thread):
	def __init__(self, interfaces):
		self.interfaces = interfaces
		self.sockets = self.initSockets()
		self.buffers = self.initBuffers()
		self.doRun = False
		Thread.__init__(self)

	def readSockets(self):
		for i in range(len(self.interfaces)):
			try:
				data = self.sockets[i].recv(4096)
				if data:
					self.buffers[i] += data
			except Exception as e:
				pass


	def initSockets(self):
		sockets = []
		for interface in self.interfaces:
			s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
			try:
				s.bind((interface, 0))
			except:
				print("Failed to bind to interface: " + interface)
			s.setblocking(False)
			sockets.append(s)
		return sockets

	def initBuffers(self):
		buffers = []
		for interface in self.interfaces :
			buffers.append(bytearray())
		return buffers

	def extractFrames(self,frames):
		slices = []
		for n in range(len(self.buffers)):
			slices.append(self.buffers[n][:frames])
			self.buffers[n] = self.buffers[n][frames:]
			slices[n] += bytes([127]) * (frames - len(slices[n]))
		if len(self.buffers) == 2 :
			chunk = [ x for y in zip(slices[0], slices[1]) for x in y ]
		elif len(self.buffers) == 1:
			chunk = slices[0]
		else:
			raise Exception("[!] Only supports 1 or two channels/interfaces.")
		return chunk, slices

	def stop(self):
		print('[LISTENER] stop()')
		self.doRun=False
		for socket in self.sockets:
			socket.close()
		self.join()

	def run(self):
		print('[LISTENER] run()')
		self.doRun=True
		while self.doRun:
			self.readSockets()

class Writer(Thread):
	def __init__(self, qtyChannels):
		self.qtyChannels = qtyChannels
		self.doRun = False
		self.buffers = self.initBuffers()
		self.chunkSize = 256
		Thread.__init__(self)

	def initBuffers(self):
		buffers = []
		for i in range(self.qtyChannels):
			buffers.append(bytearray())
		return buffers

	def stop(self):
		print('[WRITER] stop()')
		self.doRun=False
		self.join()

	def queueForPrinting(self, queueData):
		if len(queueData) != len(self.buffers):
			raise Exception("[!] len(queueData) != len(self.buffers): ",len(queueData),len(self.buffers))
		for i in range(len(self.buffers)):
			self.buffers[i]+=queueData[i]

	def run(self):
		print('[WRITER] run()')
		self.doRun=True
		while self.doRun:
			self.printBuffers()


	def printBuffers(self):
		size=0
		for n in range(len(self.buffers)):
			string = ''
			if self.chunkSize > len(self.buffers[n]):
				size = len(self.buffers[n])
			else:
				size = self.chunkSize
			for i in range(size):
				try:
					val = self.buffers[n][i]
				except:
					continue
				char=''
				if CONTROL_CHARACTERS:
					TEST = val != 127
				else:
					TEST = val > 31 and val != 127
				if TEST:
					try:
						char = chr(val)
					except:
						pass
				if char and COLOR:
					color = (val+SHIFT+256)%256
					string += '\x1b[48;5;%sm%s' % (color, char)
				else:
					print(char,end='')
					pass
			if COLOR:
				string+'\x1b[0m'
				print(string, end='')
			self.buffers[n]=self.buffers[n][size:]

# create pyaudio stream(s)
def init_pyaudio_stream():
	return PA.open(format=PA.get_format_from_width(WIDTH),
			    channels=CHANNELS,
	 		    rate=RATE,
	 		    frames_per_buffer=CHUNK,
	 		    input=False,
	 		    output_device_index=DEVICE,
	 		    output=True,
			    stream_callback=audify_data_callback)

def audify_data_callback(in_data, frame_count, time_info, status):
	frames, printQueue = sockets.extractFrames(frame_count)
	if PRINT: writer.queueForPrinting(printQueue)
	return(bytes(frames), pyaudio.paContinue)

def main():
	def signalHandler(signum, frame):
			if PRINT and COLOR:
				print('\x1b[0m',end='')

			print('\n[!] Caught termination signal: ', signum)

			# Halt the printing presses
			if PRINT:
				print('Stopping Writer...')
				try:
					writer.stop()
				except:
					print("Error stopping Writer.")

			# Shutdown the PyAudio instance
			print('Stopping audio stream...')
			try:
				PA.terminate()
			except:
				print("Failed to terminate PyAudio instance.")
			
			# close the sockets
			print('Closing Listener...')
			try:
				sockets.stop()
			except:
				print("Error closing socket.")
			print('Closing Writer...')
			
			print('Peace out!')
			sys.exit(0)

	# interrupt and terminate signal handling
	signal(SIGINT, signalHandler)
	signal(SIGTERM, signalHandler)
	signal(SIGHUP, signalHandler)

	while True:
		sleep(1)



if __name__ == "__main__":
	try:
		ap = argparse.ArgumentParser()
		ap.add_argument("-i", "--interface", required=True, help="if0[,if1] - must be a valid network interface")
		ap.add_argument("-c", "--chunk-size", type=int, default=1024, required=False, help="chunk size in frames, or samples")
		ap.add_argument("-r", "--sample-rate", type=int, default=44100, required=False, help="frames per second")
		ap.add_argument("-w", "--width", type=int, default=1, required=False, help="bytes per sample")
		ap.add_argument("-p", "--print-packet", action='store_true', default=False, required=False, help="print packet to console")
		ap.add_argument("-C", "--print-color", action='store_true', default=False, required=False, help="colorize console output")
		ap.add_argument("-S", "--print-control-characters", action='store_true', default=False, required=False, help="print utf-8 control characters")
		ap.add_argument("-s", "--color-shift", type=int, default=-127, required=False, help="color shift for colorized printing")
		ap.add_argument("-D", "--output-device", type=int, default=0, required=False, help="selects the audio output device (use helper tool for device info).")

		args = ap.parse_args()

		# check to see if user is root
		if os.getuid() != 0:
			print("Must be run as root!")
			exit(1)

		interfaces = []
		# packets = []

		ifs = re.split(r'[:;,\.\-_\+|]', args.interface)
		CHANNELS = len(ifs)

		for i in range(len(ifs)) :
			interfaces.append(ifs[i])

		DEVICE = args.output_device
		CHUNK = args.chunk_size
		RATE = args.sample_rate
		WIDTH = args.width
		PRINT = args.print_packet
		COLOR = args.print_color
		CONTROL_CHARACTERS = args.print_control_characters
		SHIFT =  min(256,max(-256,args.color_shift))
		PA = None

		print("INTERFACES: ", interfaces)
		print("CHANNELS: ", CHANNELS)
		print("CHUNK SIZE:", CHUNK)
		print("SAMPLE RATE:", RATE)
		print("BYTES PER SAMPLE:", WIDTH)

		# open the sockets
		try:
			sockets = Listener(interfaces)
			sockets.start()
		except Exception as e:
			print(e)

		# fire up the printing presses
		if PRINT:
			try:
				writer = Writer(CHANNELS)
				writer.start()
			except Exception as e:
				print(e)

		try:
			PA = pyaudio.PyAudio()
			stream = init_pyaudio_stream()
		except Exception as e:
			print("Unable to create audio stream.",e)
			sys.exit(1)

		# start the stream
		try:
			print("Starting audio stream...")
			stream.start_stream()
			if stream.is_active():
				print("Audio stream is active.")
		except Exception as e:
			print("Unable to start audio stream.",e)
			sys.exit(1)

		main()

	except Exception as e:
		print('Ooops! Exception caught:',e)
