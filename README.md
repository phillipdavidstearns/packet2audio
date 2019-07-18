# packet2audio


A minimal script to hoover up network traffic and spit it out the audio interface.

## Compatibility

Tested and working on Raspberry Pi v3 B+ (Raspbian Stretch and Buster), Debian v8-10, Kali.

Might work on Linux VMs.

Not compatible with MacOSX at the moment. Windows compatibility not tested.

## Installation

Requirements: python3, pyaudio

install pyaudio on Debian systems using:

```
$ sudo apt-get update && sudo apt-get install python3-pyaudio portaudio19-dev
$ git clone git@github.com:phillipdavidstearns/packet2audio.git
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

Simple.

Example usage: 

```
packet2audio -i wlan0
```

Can listen on more than one interface: 

```
packet2audio -i wlan0,eth0
```

Enable blocking with `-a` for audio and `-s` for socket:

```
packet2audio -i wlan0,eth0 -a -s
```
## Credits

by Phillip David Stearns 2019

Code cobbled together from examples at:

* [How to Write a Simple Packet Sniffer](http://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html)
* [Wire Callback Examples](https://people.csail.mit.edu/hubert/pyaudio/#wire-callback-example)
* [Capturing SIGINT in Python](https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python#1112350)

A nice link illuminating protocol codes in linux:

* [Linux Protocol Codes](https://github.com/torvalds/linux/blob/ead751507de86d90fa250431e9990a8b881f713c/include/uapi/linux/if_ether.h)
