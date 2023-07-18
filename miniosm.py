# A minimal osm server. Intended to serve data from an osm xml export
# SECURITY WARNING: There is no sanitaion of XML, a malicios user or data file may exhast all the memory on the machene

import http.server
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
import zlib
import io
import argparse

# Dummy capability's string
CAPSTRING = b"""
<osm version="0.6" generator="miniOSM" copyright="unkown" attribution="unknown" license="unknown">
	<api>
		<version minimum="0.6" maximum="0.6"/>
		<area maximum="10000"/>
		<note_area maximum="10000"/>
		<tracepoints per_page="5000"/>
		<waynodes maximum="10000"/>
		<relationmembers maximum="100000"/>
		<changesets maximum_elements="100000"/>
		<timeout seconds="300"/>
		<status database="online" api="online" gpx="offline"/>
	</api>
	<policy>
		<imagery>
		</imagery>
	</policy>
</osm>
"""

# Data representation

class OSM():
	def __init__(self):
		self.nodes = {}
		self.ways = {}
		self.attribution = "none loaded"
		self.copyright = "none loaded"
		self.licence = "none loaded"

class Meta():
	def __init__(self, id, user, uid, timestamp, visible, version, changeset, tags):
		self.id = id
		self.user = user
		self.uid = uid
		self.timestamp = timestamp
		self.visible = visible
		self.version = version
		self.changeset = changeset
		self.tags = tags

class Node():
	def __init__(self, meta, lat, lon):
		self.lat = lat
		self.lon = lon
		self.meta = meta

class Way():
	def __init__(self, meta):
		self.nodes = []
		self.meta = meta

# Data manipulation

def get_meta(tag):
	attrib = tag.attrib

	id = tag.get("id")
	if not id: return None
	id = int(id)

	user = str(attrib.get("user") or "unspecified")
	uid = int(attrib.get("uid") or "1")
	timestamp = str(attrib.get("timestamp") or "1990-01-01T00:00:00.00+00:00")
	visible = "false" != str(attrib.get("visible") or "true")
	version = int(attrib.get("version") or "1")
	changeset = int(attrib.get("changeset") or "1")

	tags = {}
	for subtag in tag:
		if subtag.tag == "tag":
			key = subtag.attrib["k"]
			value = subtag.attrib["v"]
			tags[key] = value

	return Meta(id, user, uid, timestamp, visible, version, changeset, tags)

def get_osm_export_element(tag, osm):
	attrib = tag.attrib
	meta = get_meta(tag)

	if tag.tag == "node":
		lat = float(tag.attrib.get("lat") or 0)
		lon = float(tag.attrib.get("lon") or 0)
		osm.nodes[meta.id] = Node(meta, lat, lon)
	elif tag.tag == "way":
		way = Way(meta)
		for subtag in tag:
			if subtag.tag == "nd":
				if subtag.attrib.get("ref"):
					way.nodes.append(int(subtag.attrib["ref"]))
		osm.ways[meta.id] = way
	elif tag.tag == "bounds":
		# Ignore the bounds tag, it is not used in the api
		pass
	else:
		print("Unknown tag type", tag.tag)

def load_osm_export(xml_string, osm):
	xml = ET.fromstring(xml_string)

	osm.copyright = xml.attrib.get("copyright") or "unspecified"
	osm.attribution = xml.attrib.get("attribution") or "unspecified"
	osm.licence = xml.attrib.get("licence") or "unspecified"

	if xml.tag != 'osm':
		print("Warning, xml file's root tag is not <osm>, it is likly not an osm export")

	for element in xml:
		get_osm_export_element(element, osm)

def apply_changeset(xml_string, osm):
	"""
	Modify a osm object by a changeset. Returns the xml to be returned to client
	May raise a KeyError or ValueError
	"""
	xml = ET.fromstring(xml_string)

	# map the negative id's from the changeset into the ids in the dataset
	node_idmap = {}
	way_idmap = {}

	def allocate_id(osm):
		"""
		Quick and dirty function to generate a numeric id that is not in the dataset
		"""
		way_ids = osm.ways.keys()
		node_ids = osm.nodes.keys()
		return max(max(way_ids), max(node_ids)) + 1

	def remap_id(id, mapdict, osm):
		if id in mapdict:
			return mapdict[id]
		newid = id
		if id < 0:
			newid = allocate_id(osm)
		mapdict[id] = newid
		return newid

	def remap_meta(meta, mapdict, osm):
		meta.id = remap_id(meta.id, mapdict, osm)
	
	def remap_and_import_node(xmlnode, osm):
		meta = get_meta(xmlnode)
		if meta == None:
			print("Missing id in changeset node, ignoring")
			return

		remap_meta(meta, node_idmap, osm)
		meta.version = meta.version + 1
		
		lat = float(xmlnode.attrib.get("lat") or 0)
		lon = float(xmlnode.attrib.get("lon") or 0)
		
		osm.nodes[meta.id] = Node(meta, lat, lon)
		
	def remap_and_import_way(xmlway, osm):
		meta = get_meta(xmlway)
		if meta == None:
			print("Missing id in changeset way, ignoring")
			return

		remap_meta(meta, way_idmap, osm)
		meta.version = meta.version + 1
		
		way = Way(meta)
	
		for subelement in element:
			if subelement.tag == "nd":
				ref = int(subelement.attrib.get("ref") or 0)
				ref = remap_id(ref, node_idmap, osm)
				way.nodes.append(ref)

		osm.ways[meta.id] = way
		
	# For newly created or modified elements, rewrite ids and import
	# Creation is handled first as modfied ways may reference newly created nodes
	for tag in xml:
		if tag.tag == "create" or tag.tag == "modify":
			for element in tag:
				if element.tag == "node":
					remap_and_import_node(element, osm)
				if element.tag == "way":
					 remap_and_import_way(element, osm)
				
		if tag.tag == "delete":
			for element in tag:
				id = element.attrib.get("id")
				if not id: print("Missing id on delete in changeset")
				id = int(id)
				if element.tag == "node" and id in osm.nodes:
					node_idmap[id] = None
					del osm.nodes[id]
				if element.tag == "way" and id in osm.ways:
					way_idmap[id] = None
					del osm.ways[id]

	root = ET.Element("diffResult")
	root.attrib["generator"] = "miniOSM"
	root.attrib["version"] = "0.6"

	def add_diff(tagname, mapdict, datadict):
		for oldid in mapdict.keys():
			xml_node = ET.SubElement(root, tagname)
			xml_node.attrib["old_id"] = str(oldid)
			if mapdict.get(oldid) and mapdict[oldid]:
				newid = mapdict[oldid]
				xml_node.attrib["new_id"] = str(newid)
				xml_node.attrib["new_version"] = str(datadict[newid].meta.version)

	add_diff("node", node_idmap, osm.nodes)
	add_diff("way", way_idmap, osm.ways)

	return root

def serialize_meta(xml, meta):
	xml.attrib["version"] = str(meta.version)
	xml.attrib["changeset"] = str(meta.changeset)
	xml.attrib["id"] = str(meta.id)
	xml.attrib["uid"] = str(meta.uid)
	xml.attrib["user"] = str(meta.user)
	xml.attrib["timestamp"] = meta.timestamp

	if meta.visible:
		xml.attrib["visible"] = 'true'
	else:
		xml.attrib["visible"] = 'false'

	for k in meta.tags.keys():
		v = meta.tags[k]
		tag = ET.SubElement(xml, "tag")
		tag.attrib["k"] = k
		tag.attrib["v"] = v

def serialize_xml(osm):
	"""
	Searialize an osm object into xml similar to an osm export
	"""
	root = ET.Element("osm")
	root.attrib["generator"] = "miniOSM"
	root.attrib["version"] = "0.6"
	root.attrib["copyright"] = osm.copyright
	root.attrib["attribution"] = osm.attribution
	root.attrib["licence"] = osm.licence

	for node in osm.nodes.values():
		xml_node = ET.SubElement(root, "node")
		serialize_meta(xml_node,node.meta)
		xml_node.attrib["lat"] = str(node.lat)
		xml_node.attrib["lon"] = str(node.lon)
	
	for way in osm.ways.values():
		xml_way = ET.SubElement(root, "way")
		serialize_meta(xml_way, way.meta)
		for nodeid in way.nodes:
			xml_nd = ET.SubElement(xml_way, "nd")
			xml_nd.attrib = {"ref": str(nodeid)}
	
	return ET.tostring(root)

# Server code

def get_in_bounding_box(osm, lat0, lat1, lon0, lon1):
	"""
	Return an OSM object containing everything within an area
	"""
	matching = OSM()
	matching.copyright = osm.copyright
	matching.licence = osm.licence
	matching.attribution = osm.attribution
	# Find nodes inside bounding box
	for node in osm.nodes.values():
		if node.lat >= lat0 and node.lat <= lat1 and node.lon >= lon0 and node.lon <= lon1:
			matching.nodes[node.meta.id] = node

	# Ways should be included if they have at least one node inside of the bounding obx
	included_ways = set()
	for way in osm.ways.values():
		for nodeid in way.nodes:
			if nodeid in matching.nodes:
				included_ways.add(way)
		
	for way in included_ways:	
		matching.ways[way.meta.id] = way
		# inlude all nodes in the included way
		for nodeid in way.nodes:
			matching.nodes[nodeid] = osm.nodes[nodeid]
	
	return matching


def normalize_path(path):
	if path.startswith("/api"):
		path = path.removeprefix("/api")
	if path.startswith("/0.6"):
		path = path.removeprefix("/0.6")
	return path

class OSMServer(http.server.HTTPServer):
	osm = OSM()
	write_file = None
	def load_xml(self, file):
		print("Loading xml file...")
		load_osm_export(file.read(), self.osm)
		print("Have", len(self.osm.nodes.keys()), "nodes")
		print("Have", len(self.osm.ways.keys()), "ways")

def receive_file(rfile, headers):
	buffer = io.BytesIO()

	if "Content-Length" in headers:
		content_length = int(headers["Content-Length"])
		body = rfile.read(content_length)
		buffer.write(body)

	elif "chunked" in headers.get("Transfer-Encoding", ""):
		while True:
			line = rfile.readline().strip()
			chunk_length = int(line, 16)
			if chunk_length != 0:
				chunk = rfile.read(chunk_length)
				buffer.write(chunk)
				rfile.readline()
			if chunk_length == 0:
				break
	else:
		print("Unable to handle upload.")
		print("Headers:", headers)
		return None

	return buffer.getvalue()

class OSMHandler(http.server.BaseHTTPRequestHandler):
	def respond_xml(self, osm):
		"""
		Searalizes and returns the passed osm objects to the client as xml
		"""
		xml = serialize_xml(osm);
		self.send_response(200)
		self.send_header("Content-type", "application/xml")
		self.send_header("Content-Length", len(xml))
		self.end_headers()
		self.wfile.write(xml);

	def unsupported(self):
		self.send_response(501)
		self.send_header("Content-type", "text/plain")
		self.send_header("Content-Length", 0)
		self.end_headers()

	def do_GET(self):
		path_elements = self.path.split("?")
		path = path_elements[0]
		path = normalize_path(path)
		query = None;
		if len(path_elements) > 1:
			query = parse_qs(path_elements[1])
		if (path == "/notes"):
			# No notes support yet, just dont return anything
			self.respond_xml(OSM())
		elif (path == "/map"):
			bbox = query["bbox"][0].split(",")
			bbox = [float(cord) for cord in bbox]
			self.respond_xml(get_in_bounding_box(self.server.osm, bbox[1],bbox[3],bbox[0],bbox[2]))
		elif (path == '/capabilities'):
			self.send_response(200)
			self.send_header("Content-type", "application/xml")
			self.send_header("Content-Length", len(CAPSTRING))
			self.end_headers()
			self.wfile.write(CAPSTRING);
		else:
			unsupported()
			print("Unhandled GET request:", self.path)

	def do_PUT(self):
		if not self.server.write_file:
			self.send_response(403)
			return
		path = normalize_path(self.path)
		if (path == "/changeset/create"):
			# Request to create a changeset, respond with a dummy id of 0
			file = receive_file(self.rfile, self.headers);

			changeset_id = b"1"
			self.send_response(200)
			self.send_header("Content-type", "text/plain")
			self.send_header("Content-Length", len(changeset_id))
			self.end_headers()
			self.wfile.write(changeset_id)
		if (path == "/changeset/1/close"):
			# Close the dummy changeset
			self.send_response(200)
			self.send_header("Content-type", "text/plain")
			self.send_header("Content-Length", 0)
			self.end_headers()
		else:
			unsupported()
			print("Unhandled PUT request:", self.path)

	def do_POST(self):
		if not self.server.write_file:
			self.send_response(403)
			return
		path = normalize_path(self.path)
		if (path == "/changeset/0/upload"):
			# Client wants to upload a changeset to the dummy id
			print("Downloading update...")
			file = receive_file(self.rfile, self.headers);
			print("Got", len(file), "bytes")
			# attept to apply the changeset
			result = None
			result = apply_changeset(file, self.server.osm)
			print("Have", len(self.server.osm.nodes.keys()), "nodes")
			print("Have", len(self.server.osm.ways.keys()), "ways")
			# Write it out to the output file
			print("Writing output file...")
			dump = serialize_xml(self.server.osm)
			with open(self.server.write_file, "wb") as file:
				file.write(dump)
			# Tell client things went right, and send the new ids
			result = ET.tostring(result)
			self.send_response(200)
			self.send_header("Content-type", "application/xml")
			self.send_header("Content-Length", len(result))
			self.end_headers()
			self.wfile.write(result)

		else:
			unsupported()
			print("Unhandled POST request:", self.path)




def run(infile, port, server_class=OSMServer, handler_class=OSMHandler, outfile = None):
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	httpd.load_xml(infile)
	httpd.write_file = outfile
	httpd.serve_forever()


parser = argparse.ArgumentParser(
	prog='miniOSM',
        description='A hacky tool to serve an osm export over the network.',
        epilog='This does not use a database so it will be rather slow on large exports')

parser.add_argument('map', help="An xml export from osm")  
parser.add_argument('-p', '--port', type=int, default=8080, help="the port to listen on")
parser.add_argument('-o', '--out', type=str, default=None, help="""
If specified, the server will accept uploads, writing the new map into the passed file.
No authenication is supported, anyone is allowed to upload.
Uploads are not atomic, a broken or interupted upload can break the state.
It is also possible to crash the server with a maliciously crafted upload.
""")  


args = parser.parse_args()
run(open(args.map), args.port, outfile=args.out)
