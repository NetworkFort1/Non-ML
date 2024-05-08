import pandas as pd
import numpy as np
import pickle as pkl
import zat
from zat.log_to_dataframe import LogToDataFrame
from urlextract import URLExtract
import re
import wordninja
from collections import Counter
import math
from elasticsearch import Elasticsearch

def clean_url(data):
    extractor = URLExtract()
    urls = data['query'].apply(lambda x: ' '.join(extractor.find_urls(x)) if extractor.find_urls(x) else x)
    return urls

def calculate_character_frequency(a):
    char_frequency = Counter(a)
    total_characters = len(a)
    entropy = -sum((freq / total_characters) * math.log2(freq / total_characters) for freq in char_frequency.values())
    return entropy

def calculate_unique(data):
    arr = []
    for i in range(len(data)):
        t_ts = []
        for j in range(i, i - 10, -1):
            ts = ""
            if j >= 0:
                ts = ".".join(data['query'][j].split('.')[:-2])
            ts = set(ts)
            t_ts.append(ts)

        intersection = t_ts[-1]
        union = t_ts[-1]
        for j in range(len(t_ts) - 1):
            intersection = intersection & t_ts[j]
            union = union | t_ts[j]
        intersection_size = len(intersection)
        union_size = len(union)

        arr.append(0 if union_size == 0 else (1 - (intersection_size / union_size)))

    return arr

def calculate_metrics(data):
    data['length'] = data['query'].apply(lambda x: len(".".join(x.split('.')[:-2])))
    data['subdomains_count'] = data['query'].apply(lambda x: x.count('.') - 1 if x.count('.') >= 2 else 0)
    data['w_count'] = data['query'].apply(lambda x: len(wordninja.split(".".join(x.split('.')[:-2]))))
    data['w_max'] = data['query'].apply(lambda x: 0 if not len(".".join(x.split('.')[:-2])) else len(max(wordninja.split(".".join(x.split('.')[:-2])), key=len)))
    data['entropy'] = data['query'].apply(lambda x: calculate_character_frequency(".".join(x.split('.')[:-2])))
    data['w_max_ratio'] = data['w_max'] / data['length']
    data['w_count_ratio'] = data['w_count'] / data['length']
    data['digits_ratio'] = data['query'].apply(lambda x: 0 if not len(".".join(x.split('.')[:-2])) else sum(1 for char in x.split('.')[-2] if char.isdigit()) / len(".".join(x.split('.')[:-2])))
    data['uppercase_ratio'] = data['query'].apply(lambda x: 0 if not len(".".join(x.split('.')[:-2])) else sum(1 for letter in x.split('.')[-2] if letter.isupper()) / len(".".join(x.split('.')[:-2])))
    data['time_avg'] = data['ts'].rolling(window=10, min_periods=1).apply(lambda x: np.mean(np.diff(x)))
    data['time_stdev'] = data['ts'].rolling(window=10, min_periods=1).apply(lambda x: np.std(np.diff(x)))
    data['size_avg'] = data['length'].rolling(window=10, min_periods=1).mean()
    data['size_stdev'] = data['length'].rolling(window=10, min_periods=1).std()
    data['unique'] = calculate_unique(data)
    data['entropy_avg'] = data['entropy'].rolling(window=10, min_periods=1).mean()
    data['entropy_stdev'] = data['entropy'].rolling(window=10, min_periods=1).std()

    return data

path = '/opt/zeek/spool/zeek/dns.log'

try:
    log_to_df = LogToDataFrame()
    print("Starting Files Data Loading")
    if path:
        columns = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','trans_id','rtt','query','qclass','qclass_name','qtype','qtype_name','rcode','rcode_name','AA','TC','RD','RA','Z','answers','TTLs','rejected']
        df = pd.read_csv(path, sep="\t", comment="#", header=None, names=columns)
        dns_log = df.drop(['uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','trans_id','rtt','qclass','qclass_name','qtype','qtype_name','rcode','rcode_name','AA','TC','RD','RA','Z','answers','TTLs','rejected'], axis=1)
        dns_log = dns_log.dropna()
        dns_log['query'] = clean_url(dns_log)
        dns_log['query'] = dns_log['query'][dns_log['query'].apply(lambda x: str(x).count('.') >= 2)]
        dns_log = dns_log.dropna(subset=['query'])
        dns_log = dns_log.reset_index()
        dns_log = calculate_metrics(dns_log)
        dns_log = dns_log.copy()
        dns_log = dns_log.dropna()
        dns_log.rename(columns={'ts': 'timestamp'}, inplace=True)
        dns_log = dns_log.drop(['index','query'], axis=1)
        print('DNS Load Successfully')
        print(dns_log.isnull().sum())
        print(dns_log.shape)

        # Send alerts to Elasticsearch
        es = Elasticsearch("http://172.16.0.34:9200")
        for index, row in dns_log.iterrows():
            doc = {
                'timestamp': row['timestamp'],
                'length': row['length'],
                'subdomains_count': row['subdomains_count'],
                'w_count': row['w_count'],
                'w_max': row['w_max'],
                'entropy': row['entropy'],
                'w_max_ratio': row['w_max_ratio'],
                'w_count_ratio': row['w_count_ratio'],
                'digits_ratio': row['digits_ratio'],
                'uppercase_ratio': row['uppercase_ratio'],
                'time_avg': row['time_avg'],
                'time_stdev': row['time_stdev'],
                'size_avg': row['size_avg'],
                'size_stdev': row['size_stdev'],
                'unique': row['unique'],
                'entropy_avg': row['entropy_avg'],
                'entropy_stdev': row['entropy_stdev']
            }
            es.index(index='dns-exfiltration_alert', body=doc)
            print("DNS Exfiltration alert sent to Elasticsearch:", doc)

    else:
        print('File not found')

except Exception as e:
    print(f"Error occurred while loading log files: {e}")