#!/usr/bin/python3
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timedelta
import dns.resolver
import requests


def query_txt_record(domain):
    try:
        # Query the TXT records for the domain
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                return txt_string.decode('utf-8')
    except:
        return None


def decide_on_root_dns_record(cur_date=None):
    if cur_date is None:
        cur_date = datetime.now()

    my_pub_ip = None
    while my_pub_ip is None:
        try:
            my_pub_ip = requests.get("https://ifconfig.me").text
        except:
            pass
    if my_pub_ip is None:
        raise Exception("Could not get my public IP. Needed for the calculation")

    root_dns_record = ""

    current_file_dir = os.path.dirname(os.path.abspath(__file__))
    words_filename = os.path.join(current_file_dir, "../remy.py")
    used_root_dns_records = ["f9367e88-ab2c-11ef-a3a5-973b07fbf7d2.artifex.co.il"]
    used_root_dns_records_filename = os.path.join(tempfile.gettempdir(), "~~" + hashlib.sha256(my_pub_ip.encode()).hexdigest())
    try:
        with open(used_root_dns_records_filename) as used_root_dns_records_file:
            used_root_dns_records = used_root_dns_records + used_root_dns_records_file.readlines()
    except:
        pass

    words_list = []
    with open(words_filename) as words_file:
        words_text_raw = words_file.read().lower()
        words_text_raw = re.sub(r'[/\\_-]]', ' ', words_text_raw)
        words_text_raw = re.sub('[^a-z]', ' ', words_text_raw)
        words_text_raw = re.sub(r'\s+', ' ', words_text_raw)
        words_list = words_text_raw.strip().split(' ')

    root_dns_record = words_list[cur_date.day * cur_date.month % len(words_list)] + "." + words_list[
        (cur_date.day * cur_date.month * cur_date.year) % len(words_list)] + str((cur_date.month * cur_date.year) % len(words_list)) + ".co.il"
    todays_root_dns_record = root_dns_record
    root_dns_record_valid = query_txt_record(root_dns_record) is not None
    used_root_dns_records_idx = len(used_root_dns_records) - 1
    while not root_dns_record_valid and used_root_dns_records_idx >= 0:
        root_dns_record = used_root_dns_records[used_root_dns_records_idx]
        root_dns_record_valid = query_txt_record(root_dns_record) is not None
        used_root_dns_records_idx -= 1

    if root_dns_record_valid and root_dns_record not in used_root_dns_records:
        used_root_dns_records += root_dns_record
        with open(used_root_dns_records_filename, "w") as used_root_dns_records_file:
            for used_root_dns_record in used_root_dns_records:
                used_root_dns_records_file.write(used_root_dns_record + "\n")

    return todays_root_dns_record, root_dns_record


def main():
    tomorrows_root_dns_record, root_dns_record = decide_on_root_dns_record(cur_date=datetime.now() + timedelta(1))
    todays_root_dns_record, root_dns_record = decide_on_root_dns_record()
    print(json.dumps({
        "todays_root_dns_record": todays_root_dns_record,
        "tomorrows_root_dns_record": tomorrows_root_dns_record,
        "currently_used_root_dns_record": root_dns_record
    }, indent=4))


main()
