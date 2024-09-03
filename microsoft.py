import scraper

# Example usage
def main():

    # URL for Cisco advisories
    url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?$orderBy=releaseDate%20desc"
    raw_data = scraper.get_json_from_url(url)["value"]
    print("Data fetched.")
    # Example vendor
    vendor_name = "Microsoft"
    source = "https://msrc.microsoft.com/update-guide/vulnerability"
    vendor_id = scraper.insert_vendor(vendor_name, source)

    print("Vendor inserted.")
    
    data =[]
    for entry in raw_data[:10]:
        new_entry = {
            "identifier": entry["id"],
            "title": entry["cveTitle"],
            "firstPublished": entry["releaseDate"],
            "url": "https://msrc.microsoft.com/update-guide/vulnerability/"+entry["cveNumber"],
            "cve": entry["cveNumber"]
        }
        data.append(new_entry)
    
    if data:
        new_advisories = scraper.check_for_new_advisories(data, vendor_id)

        titles = [advisory['title'] for advisory in new_advisories]
        print("New advisories: ", titles)
        for advisory in new_advisories:
            print("ADVISORY : ", advisory['identifier'], " / ", advisory['title'])
            cves = advisory['cve']
            cve_array = cves.split(",")
            scraper.process_cve(cve_array, advisory['identifier'])
    
if __name__ == "__main__":
    main()
