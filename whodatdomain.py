#!python3

import pythonwhois
import tldextract
import csv

counter = 0

with open("hits.csv", "w", newline="") as report:
    writer = csv.writer(report)

with open("splunk_domains.txt", "r") as domains:
    for domain in domains:
        counter += 1
        try:
            ext = tldextract.extract(domain)
            domain = ext.registered_domain
            # print(domain)
            w = pythonwhois.get_whois(domain)
            registrar = w["registrar"][0]
            created = w["creation_date"]
            emails = w["emails"]
            nameservers = w["nameservers"]
            contacts = w["contacts"]

            if "namecheap" in str.lower(registrar):
                record = [domain, registrar, created, emails, nameservers, contacts]
                print(record)
                writer.writerow(record)
        except:
            print("Error with {0}. {1} domains processed.".format(domain, counter))
            # print("Error with " + domain + ". " + counter + " domains processed. ")
