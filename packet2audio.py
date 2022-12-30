#!/usr/bin/env python3
'''============================================================================
packet2audio
by Phillip David Stearns

example usage: sudo python3 packet2audio.py -i wlan0

A minimal script to hoover up network traffic and spit it out the audio interface.
Non-blocking by design. Why would you ever want any of these things to block? LMK!

After undergoing several overhauls, the current approach taken is to run the three
diffferent IO tasks in separate threads. When running on a RPi v3 B+, audio
plays back with minimal cutout. Printing to the console seems to cause interruptions
and blocking between threads. Still some figuring out to be done here.

Tested and working on Raspberry Pi v3 B+ (Raspbian Stretch), Debian 9.9, Kali Linux
Might work on Debian VMs (untested)
Compatible with python3
Not compatible with MacOSX (tested).x
Windows compatibility not tested.

Requirements: pyaudio

install pyaudio on Debian systems using:

$ sudo apt-get update && sudo apt-get install python3-pyaudio -y

Code cobbled together from examples at:

http://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html
https://people.csail.mit.edu/hubert/pyaudio/#wire-callback-example
https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python#1112350

A nice link illuminating protocol codes in linux
https://github.com/torvalds/linux/blob/ead751507de86d90fa250431e9990a8b881f713c/include/uapi/linux/if_ether.h
============================================================================='''

# modules
import os
import sys
import argparse
from signal import *
import socket
import pyaudio
import re
from threading import Thread
from time import sleep

#===========================================================================
# Listener
# A socket based packet sniffer. Main loop will check sockets for data and grab what's there,
# storing in a buffer to be extracted later. chunkSize should be a relatively small power of two.
# Until I can figure out a way to tinker with the sockets and set appropriate permissions, this
# is what requires running the script as root.

class Listener(Thread):
	def __init__(self, interfaces, chunkSize=4096):
		self.interfaces = interfaces
		self.chunkSize = chunkSize # used to fine tune how much is "grabbed" from the socket
		self.sockets = self.initSockets()
		self.buffers = self.initBuffers() # data will be into and out of the buffer(s)
		self.doRun = False # flag to run main loop & help w/ smooth shutdown of thread
		Thread.__init__(self)

	def initSockets(self):
		sockets = []
		for interface in self.interfaces:
			# etablishes a RAW socket on the given interface, e.g. eth0. meant to only be read.
			s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
			s.bind((interface, 0))
			s.setblocking(False) # non-blocking
			sockets.append(s)
		return sockets

	def initBuffers(self):
		# nothing up my sleeves here...
		buffers = []
		for interface in self.interfaces :
			buffers.append(bytearray())
		return buffers

	def readSockets(self):
		for i in range(len(self.sockets)):
			try: # grab a chunk of data from the socket...
				data = self.sockets[i].recv(self.chunkSize)
				if data: self.buffers[i] += data # if there's any data there, add it to the buffer
			except: # if there's definitely no data to be read. the socket will throw and exception
				pass

	def extractFrames(self, frames):
		# places to put stuff...
		slices = [] # for making the chunk of audio data
		printQueue = [] # for assembling the data into chunks for printing
		for n in range(len(self.buffers)):
			bufferSlice = self.buffers[n][:frames] # grab a slice of data from the buffer
			printQueue.append(bufferSlice) # whatever we got, add it to the print queue. no need to pad
			# this makes sure we return as many frames as requested, by padding with audio "0"
			padded = bufferSlice + bytes([127]) * (frames - len(bufferSlice))
			slices.append(padded)
			self.buffers[n] = self.buffers[n][frames:] # remove the extracted data from the buffer
		if len(self.buffers) == 2 : # interleave the slices to form a stereo chunk
			audioChunk = [ x for y in zip(slices[0], slices[1]) for x in y ]
		elif len(self.buffers) == 1: # marvelous mono
			audioChunk = slices[0]
		else:
			raise Exception("[!] Only supports 1 or two channels/interfaces.")
		return audioChunk, printQueue

	def run(self):
		print('[LISTENER] run()')
		self.doRun=True
		while self.doRun:
			sleep(0.0001)
			self.readSockets()

	def stop(self):
		print('[LISTENER] stop()')
		self.doRun=False
		for socket in self.sockets:
			socket.close()
		self.join()

#===========================================================================
# Writer
# Handles console print operations in an independent thread. To prevent backlog of print data,
# The chunkSize should be set to the same value as for the audio device. Right now, this is done
# in the initialization portion of the script when run as standalone.

class Writer(Thread):
	def __init__(self, qtyChannels, chunkSize=4096):
		self.qtyChannels = qtyChannels # we need to know how many streams of data we'll be printing
		self.doRun = False
		self.buffers = self.initBuffers() # the so called printQueue
		self.chunkSize = chunkSize
		Thread.__init__(self)

	def initBuffers(self):
		buffers = []
		for i in range(self.qtyChannels):
			buffers.append(bytearray())
		return buffers

	def queueForPrinting(self, queueData):
		# since this thread isn't actively grabbing data, it's added here...
		if len(queueData) != len(self.buffers):
			raise Exception("[!] len(queueData) != len(self.buffers): ",len(queueData),len(self.buffers))
		for i in range(len(self.buffers)):
			self.buffers[i]+=queueData[i]

	def printBuffers(self):
		# assembles a string to be printed for each stream in the buffers.
		size = 0
		for n in range(len(self.buffers)):
			string = ''
			# if there's less data in the buffer than the chunkSize, we print only what is there
			if self.chunkSize > len(self.buffers[n]):
				size = len(self.buffers[n])
			else:
				size = self.chunkSize

			for i in range(size):
				char=chr(0) # for some reason, setting the character to utf-8 encoded 'null' works best
				val = self.buffers[n][i] # used to be wrapped in a try/except block... shouldn't be necessary now

				# if we want to try to print everything, including control characters...
				if CONTROL_CHARACTERS:
					TEST = True
				else:
					TEST = val > 31

				if TEST:
					try: # there may be times when the value doesn't map to a valid utf-8 character
						char = chr(val)
					except: # just skip it...
						pass
				if COLOR: # add the ANSI escape sequence to encode the background color to value of val
					color = (val+SHIFT+256)%256 # if we want to specify some amount of color shift...
					string += '\x1b[48;5;%sm%s' % (color, char)
				else:
					string+=char
			if COLOR: string+='\x1b[0m' # terminate the string with the ANSI reset escape sequence
			print(string, end='') # the thing we came all this way to do
			self.buffers[n]=self.buffers[n][size:] # remove the printed bit from the buffers

	def run(self):
		print('[WRITER] run()')
		self.doRun=True
		while self.doRun:
			sleep(0.0001)
			self.printBuffers()

	def stop(self):
		print('[WRITER] stop()')
		self.doRun=False
		self.join()

#===========================================================================
# Audifer
# Class run in its own thread which handles PyAudio stream instance and operations
# Callback mode is used. Documentation for PyAudio states the process
# for playback runs in a separate thread. Initializing in a subclassed Thread may be redundant.

class Audifier(Thread):
	def __init__(self, qtyChannels, width=1, rate=44100, chunkSize=2048, deviceIndex=0):
		self.doRun=False
		self.qtyChannels = qtyChannels
		self.width = width
		self.rate = rate
		self.chunkSize = chunkSize
		self.deviceIndex = deviceIndex
		self.pa = pyaudio.PyAudio()
		self.stream = self.initPyAudioStream()
		Thread.__init__(self)

	def initPyAudioStream(self):
		return self.pa.open(format=self.pa.get_format_from_width(self.width),
			channels=self.qtyChannels,
	 		rate=self.rate,
	 		frames_per_buffer=self.chunkSize,
	 		input=False,
	 		output_device_index=self.deviceIndex,
	 		output=True,
			stream_callback=audify_data_callback)

	def run(self):
		print('[AUDIFIER] run()')
		# start the stream
		print("Starting audio stream...")
		self.stream.start_stream()
		if self.stream.is_active(): print("Audio stream is active.")

		while self.doRun:
			sleep(0.1)

	def stop(self):
		print('[AUDIFIER] stop()')
		self.doRun = False
		self.pa.terminate()
		self.join()

#===========================================================================
# callbak for PyAudio stream instance in Audifier

def audify_data_callback(in_data, frame_count, time_info, status):
	audioChunk, printQueue = sockets.extractFrames(frame_count)
	if PRINT: writer.queueForPrinting(printQueue)
	return(bytes(audioChunk), pyaudio.paContinue)

#===========================================================================
# Signal Handler / shutdown procedure

def signalHandler(signum, frame):
	print('\n[!] Caught termination signal: ', signum)
	shutdown()

def shutdown():
	# Just to make sure the console formatting returns to "normal"
	if PRINT and COLOR:
		print('\x1b[0m',end='')

	# Halt the printing presses
	if PRINT:
		print('Stopping Writer...')
		try:
			writer.stop()
		except Exception as e:
			print("Error stopping Writer:",e)

	# Shutdown the PyAudio instance
	print('Stopping audio stream...')
	try:
		audifier.stop()
	except Exception as e:
		print("Failed to terminate PyAudio instance:",e)

	# close the sockets
	print('Closing Listener...')
	try:
		sockets.stop()
	except Exception as e:
		print("Error closing socket:",e)

	print('Peace out!')
	sys.exit(0)

#===========================================================================
# main()

def main():

	# signal handling for termination, etc.
	signal(SIGINT, signalHandler)
	signal(SIGTERM, signalHandler)
	signal(SIGHUP, signalHandler)

	while True:
		sleep(1)

#===========================================================================
# Executed when run as stand alone

if __name__ == "__main__":
	try:
		ap = argparse.ArgumentParser()
		ap.add_argument("-i", "--interface", required=True, help="if0[,if1] - must be a valid network interface")
		ap.add_argument("-c", "--chunk-size", type=int, default=2048, required=False, help="chunk size in frames, or samples")
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
		ifs = re.split(r'[:;,\.\-_\+|]', args.interface)
		for i in range(len(ifs)) :
			interfaces.append(ifs[i])

		CHANNELS = len(interfaces)
		DEVICE = args.output_device
		CHUNK = args.chunk_size
		RATE = args.sample_rate
		WIDTH = args.width
		PRINT = args.print_packet
		COLOR = args.print_color
		CONTROL_CHARACTERS = args.print_control_characters
		SHIFT =  min(256,max(-256,args.color_shift))

		print("INTERFACES: ", interfaces)
		print("CHANNELS: ", CHANNELS)
		print("CHUNK SIZE:", CHUNK)
		print("SAMPLE RATE:", RATE)
		print("BYTES PER SAMPLE:", WIDTH)

		# open the sockets
		sockets = Listener(interfaces)
		sockets.start()

		# fire up the printing presses
		if PRINT:
			writer = Writer(CHANNELS, CHUNK*CHANNELS)
			writer.start()

		# spin up the audio playback engine
		audifier = Audifier(CHANNELS, WIDTH, RATE, CHUNK, DEVICE)
		audifier.start()

		# run the main loop
		main()
	except Exception as e:
		print('Ooops! Exception caught:',e)
