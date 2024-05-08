import pandas as pd
import numpy as np
import pickle as pkl
import ipaddress
from ipaddress import ip_address
from elasticsearch import Elasticsearch
import subprocess
import warnings
# Suppress a specific warning
warnings.filterwarnings("ignore", message="Specific warning message")


path ='/opt/zeek/spool/zeek/conn.log'
try:
    # load the elasticsearch instance
    try:
        es = Elasticsearch("http://172.16.0.34:9200")
    except Exception as e:
        raise Exception(e)

    # Parse the log file
    with subprocess.Popen(['tail', '-f', path], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as proc:
        for line in proc.stdout:
            line = line.rstrip('\n')
            if line and line[0] != '#':
                line = line.split('\t')
                ts = line[0]
                id_resp_p = line[5]
                proto = line[6]
                duration = line[8]
                missed_bytes = line[14]
                orig_pkts = line[16]
                orig_ip_bytes = line[17]

                # Convert data to DataFrame
                df = pd.DataFrame({'id.resp_p': [id_resp_p], 'proto': [proto], 'duration': [duration], 'missed_bytes': [missed_bytes], 'orig_pkts': [orig_pkts], 'orig_ip_bytes': [orig_ip_bytes]})
                
                # Preprocess data
                df['id.resp_p'] = df['id.resp_p'].replace('-', '0').astype(int)
                df['duration'] = df['duration'].replace('-', '0').astype(float)
                df['missed_bytes'] = df['missed_bytes'].replace('-', '0').astype(int)
                df['orig_pkts'] = df['orig_pkts'].replace('-', '0').astype(int)
                df['orig_ip_bytes'] = df['orig_ip_bytes'].replace('-', '0').astype(int)
                df['proto'] = df['proto'].replace('-', np.nan)
                df = df.dropna()

                # Send labeled data to Elasticsearch
                for index, row in df.iterrows():
                    features = row.to_dict()
                    es.index(index='ddos-alert', body=features)
                    print("DDoS alert sent to Elasticsearch:", features)

except Exception as e:
    print(f"Error occurred while loading log files: {e}")
    exit()