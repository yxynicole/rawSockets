def save_file(response, path):
	filename = path.split('/')[-1]
	if not filename: filename = 'index.html'
	print('writting to file', filename)
	with open(filename, "w") as f:
		f.write(response)


def extract_hostname_and_path(url):
	if url.startswith('http://'):
		url = url[7:]
	return url.split('/')[0], '/' + '/'.join(url.split('/')[1:])