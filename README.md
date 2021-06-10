# LycoSTand

LycoSTand is a tool which forms network flows and extracts features characterising them to understand network traffic.
Lycos is the greek word for wolf (flow in reverse order).

These characteristics can be used for network intrusion detection systems.


## Installation

* Install LIBPCAP library\
  sudo apt-get install libpcap-dev

* Retrieve code from Github\
  git clone https://github.com/17204612710214/lycostand.git \
  cd lycostand

* Retrieve PCAP files from https://www.unb.ca/cic/datasets/ids-2017.html (download link at bottom page)\
  Put PCAP files in lycostand/pcap/


* Compile code (install gcc before compiling, if not already installed):\
  make

## Execution

* Launch LycoSTand\
  ./lycostand -i ./pcap/ -o ./pcap_lycos/

IMPORTANT NOTE:
LycoSTand will process all PCAP files located in ./pcap/ folder.
Each file will be processed one after the other (multi-threading not implemented in this version).
It may take up to 16 hours on a laptop with a Core i7-8750H.
In order to speed up the processing and if your machine is multi-core, it is possible to activate a compiler switch called ARG_BYPASS in options.def and to uncomment a single pcap file to process in the main function.
Once the program is modified, compiled and launched, it is possible to repeat the process with other PCAP files while the first ones are running.
All the programs can then execute in parallel reducing the total time necessary to generate CSV files in ./pcap_lycos directory.

## Outputs

The program generates 5 CSV files (one for each PCAP file) in ./pcap_lycos/

For convenience, we provide them in zip files.
