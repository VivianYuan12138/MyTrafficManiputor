import argparse
import sys
import numpy as np
import BytesEncodingFE

if __name__ == "__main__":

    parse = argparse.ArgumentParser()

    parse.add_argument('-i', '--input_path', type=str, required=True, help="raw traffic (.pcap) path")
    parse.add_argument('-o', '--output_path', type=str, required=True, help="feature vectors (.npy) path")

    arg = parse.parse_args()
    pcap_file = arg.input_path

    feat_file = arg.output_path

    extractor=BytesEncodingFE.BytesEncoding(pcap_file,feat_file)
