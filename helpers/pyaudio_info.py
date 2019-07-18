#!/usr/bin/python3
import pyaudio

pa = pyaudio.PyAudio()

def tab(count=1):
	indent=""
	tab="\t"
	for i in range (count):
		indent+=tab
	return indent

# HOST API INFO

print("HOST INFO:")

for HOST_INDEX in range (pa.get_host_api_count()):
	print(tab()+"HOST: "+str(HOST_INDEX))
	HOST = pa.get_host_api_info_by_index(HOST_INDEX)
	for KEY in HOST:
		print(tab(2)+str(KEY)+": "+str(HOST[KEY]))
	print(tab(3)+"DEVICE INFO:")
	for DEV_INDEX in range (HOST['deviceCount']):
		print(tab(4)+"DEVICE: "+str(DEV_INDEX))
		DEVICE = pa.get_device_info_by_host_api_device_index(HOST_INDEX, DEV_INDEX)
		for KEY in DEVICE:
			print(tab(5)+str(KEY)+": "+str(DEVICE[KEY]))

