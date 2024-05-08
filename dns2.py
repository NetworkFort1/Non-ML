import pandas as pd
import os
import glob
import ipaddress
from ipaddress import ip_address
from zat.log_to_dataframe import LogToDataFrame
from elasticsearch import Elasticsearch

print('imported All required Libraries')

path = '/opt/zeek/spool/zeek/*.log'
csv_files = glob.glob(os.path.join(path))
arr=[]

try:
    print('Zeek logs File Path Found Succesfully')
    for f in csv_files:
        r = f.split('/')[-1]  # Changed to handle both Unix and Windows paths
        m = r.split('.')[0]
        arr.append(f)
    print(arr)
except Exception as e:
    print(f"Error occurred while reading file path: {e}")
    exit()

route = '/opt/zeek/spool/zeek/'

def Ip_To_int(ip):
    arr=[]
    try:
        for i in ip:
            if type(ip_address(str(i))) is ipaddress.IPv4Address:
                r = int(ipaddress.IPv4Address(str(i)))
            if type(ip_address(str(i))) is ipaddress.IPv6Address:
                r = int(ipaddress.IPv6Address(str(i)))
            arr.append(r)    
        return arr
    except Exception as e:
        print(f"Error occurred while converting IP addresses: {e}")
        exit()

try:
    log_to_df = LogToDataFrame()
    print("Starting Files Data Loading")
    for i in arr:
        if i == '/opt/zeek/spool/zeek/dns.log':
            dns_log = log_to_df.create_dataframe(route+"dns.log")
            dns_log = dns_log.dropna()
            print('DNS Load Succesfully')
        if i == '/opt/zeek/spool/zeek/conn.log':
            conn_log = log_to_df.create_dataframe(route+"conn.log")
            conn_log = conn_log.dropna()
            conn_log['dns_connection'] = (conn_log['proto'] == 'udp') & (conn_log['id.resp_p'] == 53)
            print('Conn Load Succesfully')
        if i == '/opt/zeek/spool/zeek/weird.log':
            weird_log = log_to_df.create_dataframe(route+"weird.log")
            weird_log = weird_log.dropna()
            weird_log['large_dns_query_count'] = weird_log['name'].str.startswith('dns_large_query_count')
            weird_dns_log = weird_log[weird_log['large_dns_query_count']]
            weird_dns_log['domain'] = weird_dns_log['name'].str.split('_').str[-1]
            weird_dns_query_counts = weird_dns_log['domain'].value_counts() 
            weird_dns_threshold = 10000
            suspicious_weird_domains = weird_dns_query_counts[weird_dns_query_counts > weird_dns_threshold].index
            weird_dns_log['suspicious_domain'] = weird_dns_log['domain'].apply(lambda x: x in suspicious_weird_domains)
            print('Weird Load Succesfully')
except Exception as e:
    print(f"Error occurred while loading log files: {e}")
    exit()

print('Start Data Preprocessing')

try:
    merged_log = pd.merge(dns_log, conn_log, on=['id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto'], how='outer')
    merged_log = pd.merge(merged_log, weird_dns_log, on=['id.orig_h','id.orig_p','id.resp_h','id.resp_p'], how='outer')
    merged_log = merged_log.loc[:, ['id.orig_h','id.orig_p','id.resp_h','id.resp_p','query','proto','dns_connection']]
    merged_log['id.orig_h'] = Ip_To_int(merged_log['id.orig_h'])
    merged_log['id.resp_h'] = Ip_To_int(merged_log['id.resp_h'])
    merged_log['query'] = merged_log['query'].astype('category')
    merged_log['query'] = merged_log['query'].cat.set_categories([1, 0])
    merged_log['query'] = merged_log['query'].fillna(0)
    merged_log.loc[merged_log['query'] != 1, 'query'] = 0
    merged_log['dns_connection'] = merged_log['dns_connection'].fillna(False)
    merged_log['query'] = merged_log['query'].cat.add_categories(['0','1'])

    # Set categories for 'proto' column
    merged_log['proto'] = merged_log['proto'].astype('category')
    merged_log['proto'] = merged_log['proto'].cat.add_categories(['unknown'])
    merged_log['proto'] = merged_log['proto'].fillna('unknown')

    merged_log.to_csv('data.csv')

    print('Data Preprocessing Complete Successfully')

    # Initialize Elasticsearch client
    es = Elasticsearch("http://172.16.0.34:9200")

    # Indexing labeled data to Elasticsearch
    for idx, row in merged_log.iterrows():
        es.index(index="dns-alerts", body=row.to_dict())
        print("DNS alert send to Elasticsearch:", row.to_dict())  # Print statement

except Exception as e:
    print(f"Error occurred during data preprocessing or Elasticsearch indexing: {e}")
    exit()