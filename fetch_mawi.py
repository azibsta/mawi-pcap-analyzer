import os
import urllib.request
import gzip
import shutil
import time

MISSING_YEARS = [2007, 2008, 2009, 2010, 2011, 2012, 2013, 2015, 2016, 2017, 2018, 2020, 2021]
BASE_URL = "http://mawi.wide.ad.jp/mawi/samplepoint-F/{year}/"
DATA_DIR = "data"

def download_and_extract(year):
    year_dir = os.path.join(DATA_DIR, str(year))
    os.makedirs(year_dir, exist_ok=True)
    
    file_bases = [f"{year}06151400.dump.gz", f"{year}06151400.pcap.gz"]
    pcap_path = os.path.join(year_dir, f"{year}06151400.pcap")
    
    if os.path.exists(pcap_path):
        print(f"[{year}] Already exists, skipping.")
        return

    for base in file_bases:
        url = BASE_URL.format(year=year) + base
        gz_path = os.path.join(year_dir, base)
        
        print(f"[{year}] Trying to download {url}...")
        try:
            req = urllib.request.Request(url, method="HEAD")
            urllib.request.urlopen(req)
            
            print(f"[{year}] Downloading...")
            urllib.request.urlretrieve(url, gz_path)
            
            print(f"[{year}] Extracting to {pcap_path}...")
            with gzip.open(gz_path, 'rb') as f_in:
                with open(pcap_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            print(f"[{year}] Cleaning up compressed file...")
            os.remove(gz_path)
            
            print(f"[{year}] Done!")
            return
            
        except Exception as e:
            print(f"[{year}] Failed with {base}: {e}")
            if os.path.exists(gz_path):
                os.remove(gz_path)
            
    print(f"[{year}] ERROR: Could not find a valid file to download.")

if __name__ == '__main__':
    print("Starting MAWI automated download process...")
    for y in MISSING_YEARS:
        download_and_extract(y)
        time.sleep(2)
    
    print("All downloads complete!")
