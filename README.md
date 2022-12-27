# packet2audio


A minimal python script to hoover up network traffic and spit it out the audio interface. Managing of Sockets, Printing and Audification are handled in separate threads.

## Compatibility

Tested and working on Raspberry Pi v3 B+ (Raspbian Stretch and Buster), Debian v8-10, Kali.

Might work on Linux VMs.

Not compatible with MacOSX at the moment. Windows compatibility not tested.

## Installation

Requirements: python3, pyaudio

install pyaudio on Debian systems using:

```
$ sudo apt-get update && sudo apt-get install python3-pyaudio portaudio19-dev
```
clone the repo:

```
$ git clone https://github.com/phillipdavidstearns/packet2audio.git
```

Create a symlink for handy command line usage:

```
$ sudo ln -s /path/to/packet2audio/packet2audio.py /usr/local/bin/packet2audio
```

Run with:

```
$ packet2audio -i <iface_name>
```

## Usage

Print the helper:

```
packet2audio -h
```

### Examples:

Listen to WiFi traffic: 

```
sudo packet2audio -i wlan0
```

Listen on more than one interface: 

```
sudo packet2audio -i wlan0,eth0
```

Print to stdout the data written to the audio buffer with `-p` ('utf-8' decoded):

```
sudo packet2audio -i wlan0 -p
```

Colorize the stdout characters:

```
sudo packet2audio -i wlan0 -pC
```

## Credits

by Phillip David Stearns

Code cobbled together from examples at:

* [How to Write a Simple Packet Sniffer](http://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html)
* [Wire Callback Examples](https://people.csail.mit.edu/hubert/pyaudio/#wire-callback-example)
* [Capturing SIGINT in Python](https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python#1112350)

A nice link illuminating protocol codes in linux:

* [Linux Protocol Codes](https://github.com/torvalds/linux/blob/ead751507de86d90fa250431e9990a8b881f713c/include/uapi/linux/if_ether.h)
