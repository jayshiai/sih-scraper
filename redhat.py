import scraper
import requests
from bs4 import BeautifulSoup
# Example usage
def main():
    rows = 150
    url="https://access.redhat.com/hydra/rest/search/kcs?q=*%3A*&start=0&hl=true&hl.fl=lab_description&hl.simple.pre=%253Cmark%253E&hl.simple.post=%253C%252Fmark%253E&fq=portal_advisory_type%3A%28%22Security+Advisory%22%29+AND+documentKind%3A%28%22Errata%22%29&facet=true&facet.mincount=1&rows="+str(rows)+"&fl=id%2Cportal_severity%2Cportal_product_names%2Cportal_publication_date%2Cportal_synopsis%2Cview_uri%2CallTitle&sort=portal_publication_date+desc&p=1&facet.field=portal_severity&facet.field=portal_advisory_type"
    data = scraper.get_json_from_url(url)["response"]["docs"]
    # print("Data fetched:", data)
    # # Example vendor
    vendor_name = "Red Hat"
    source = "https://access.redhat.com/security/security-updates/security-advisories"
    vendor_id = scraper.insert_vendor(vendor_name, source)

    print("Vendor inserted.")

    new_data = []
    for entry in data:
        new_entry = {
             "identifier": entry["id"],
            "title": entry["allTitle"],
            "firstPublished": entry["portal_publication_date"],
            "url": entry["view_uri"],
        }
        new_data.append(new_entry)
    
    # print("New data: ", new_data)
    if new_data:
        new_advisories = scraper.check_for_new_advisories(new_data, vendor_id)


    for advisory in new_advisories:
        print("Fetching Link: ", advisory['url'])
        response = requests.get(advisory['url'])
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            cve_elements = soup.select('#cves ul li a')
            cves = [cve_element.text for cve_element in cve_elements]
            print("CVEs: ", cves)
            scraper.process_cve(cves, advisory['identifier'])
    #     titles = [advisory['title'] for advisory in new_advisories]
    #     print("New advisories: ", titles)
    #     for advisory in new_advisories:
    #         print("ADVISORY : ", advisory['identifier'], " / ", advisory['title'])
    #         cves = advisory['cve']
    #         cve_array = cves.split(",")
    #         scraper.process_cve(cve_array, advisory['identifier'])

if __name__ == "__main__":
    main()
