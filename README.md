# packet2audio


A minimal python script to hoover up network traffic and spit it out the audio interface.

## Compatibility

Tested and working on Raspberry Pi v3 B+ (Raspbian Stretch and Buster), Debian v8-10, Kali.

Might work on Linux VMs.

Not compatible with MacOSX at the moment. Windows compatibility not tested.

## Installation

Requirements: python3, pyaudio

install pyaudio on Debian systems using:

```
$ sudo apt-get update && sudo apt-get install python3-pyaudio portaudio19-dev
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

Simple, but it must be run as root (with `sudo`):

```
usage: packet2audio [-h] [-a] [-s] -i INTERFACE [-c CHUNK_SIZE]
                    [-r SAMPLE_RATE] [-w WIDTH] [-t TIMEOUT] [-p]

optional arguments:
  -h, --help            show this help message and exit
  -a, --audio-blocking  non-blocking by default
  -s, --socket-blocking
                        non-blocking by default
  -i INTERFACE, --interface INTERFACE
                        [if0[,if1]]
  -c CHUNK_SIZE, --chunk-size CHUNK_SIZE
                        chunk size in frames
  -r SAMPLE_RATE, --sample-rate SAMPLE_RATE
                        frames per second
  -w WIDTH, --width WIDTH
                        bytes per sample
  -t TIMEOUT, --timeout TIMEOUT
                        socket timeout in seconds
  -p, --print-packet    print packet to console
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

Enable blocking with `-a` for audio and `-s` for socket:

```
sudo packet2audio -i wlan0,eth0 -a -s
```

Print the data written to the audio buffer with `-p` (hint: doesn't make sense to use without a monitor):

```
sudo packet2audio -i wlan0 -p
```

## Credits

by Phillip David Stearns 2019

Code cobbled together from examples at:

* [How to Write a Simple Packet Sniffer](http://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html)
* [Wire Callback Examples](https://people.csail.mit.edu/hubert/pyaudio/#wire-callback-example)
* [Capturing SIGINT in Python](https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python#1112350)

A nice link illuminating protocol codes in linux:

* [Linux Protocol Codes](https://github.com/torvalds/linux/blob/ead751507de86d90fa250431e9990a8b881f713c/include/uapi/linux/if_ether.h)
