import pymongo
from datetime import datetime

def connect_to_mongo():
    # Connect to the MongoDB server and select the required database and collections
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['ssl_project']
    certstream_collection = db['certstream_results']
    zgrab2_collection = db['zgrab2_results']
    return certstream_collection, zgrab2_collection

def analyze_cert_usage(certstream_collection, zgrab2_collection):
    # Iterate over all the documents in certstream_results
    for cert in certstream_collection.find():
        domain = cert.get("domain")
        serial_number = cert.get("serial_number")
        store_timestamp = cert.get("store_timestamp")
        
        # Convert certstream store timestamp to datetime
        cert_timestamp = datetime.strptime(store_timestamp, "%Y-%m-%dT%H:%M:%SZ")
        
        # Search for corresponding entries in zgrab2_results by matching the domain
        zgrab2_results = zgrab2_collection.find({"domain": domain})
        for zgrab in zgrab2_results:
            zgrab_cert = zgrab.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {}).get("server_certificates", {}).get("certificate", {}).get("parsed", {})
            zgrab_serial_number = zgrab_cert.get("serial_number")
            zgrab_timestamp = zgrab.get("data", {}).get("tls", {}).get("timestamp")
            
            if zgrab_timestamp:
                # Convert zgrab2 timestamp to datetime
                zgrab_time = datetime.strptime(zgrab_timestamp, "%Y-%m-%dT%H:%M:%S%z")
                # Compare if the certificate used by the domain matches the one issued recently in certstream
                if serial_number == zgrab_serial_number:
                    print(f"Domain: {domain} uses the newly issued certificate as of {zgrab_time}")
                else:
                    print(f"Domain: {domain} has a new certificate issued, but it is still using an older certificate as of {zgrab_time}")

def main():
    certstream_collection, zgrab2_collection = connect_to_mongo()
    analyze_cert_usage(certstream_collection, zgrab2_collection)

if __name__ == "__main__":
    main()
