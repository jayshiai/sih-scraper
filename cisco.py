import scraper

# Example usage
def main():
    # URL for Cisco advisories
    url = "https://sec.cloudapps.cisco.com/security/center/publicationService.x?criteria=exact&cves=&keyword=&last_published_date=&limit=20&offset=0&publicationTypeIDs=1,3&securityImpactRatings=&sort=-day_sir&title="
    data = scraper.get_json_from_url(url)
    print("Data fetched.")
    # Example vendor
    vendor_name = "Cisco"
    source = "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"
    vendor_id = scraper.insert_vendor(vendor_name, source)

    print("Vendor inserted.")

    new_data = []
    for entry in data:
        new_entry = {
             "identifier": entry["identifier"],
            "title": entry["title"],
            "firstPublished": entry["lastPublished"],
            "url": entry["url"],
            "cve": entry["cve"]
        }
        new_data.append(new_entry)
    
    # print("New data: ", new_data)
    if new_data:
        new_advisories = scraper.check_for_new_advisories(new_data, vendor_id)

        titles = [advisory['title'] for advisory in new_advisories]
        print("New advisories: ", titles)
        for advisory in new_advisories:
            print("ADVISORY : ", advisory['identifier'], " / ", advisory['title'])
            cves = advisory['cve']
            cve_array = cves.split(",")
            scraper.process_cve(cve_array, advisory['identifier'])

if __name__ == "__main__":
    main()
