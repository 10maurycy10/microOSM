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

class Node():
	def __init__(self, nodeid, lat, lon, version):
		self.tags = {}
		self.nodeid = nodeid
		self.lat = lat
		self.lon = lon
		self.version = version

class Way():
	def __init__(self, wayid, version):
		self.tags = {}
		self.nodes = []
		self.wayid = wayid
		self.version = version

def load_osm_export_tag(tag, osm):
	"""
	Attempts to import a single tag of from the osm export into the osm object.
	May raise a KeyError or ValueError.
	"""
	attrib = tag.attrib
	if tag.tag == "node":
		nodeid = int(attrib["id"]);
		node = Node(nodeid, float(attrib["lat"]), float(attrib["lon"]), int(attrib.get("version") or 1))
		# Record the tags of the node
		for subtag in tag:
			if subtag.tag == "tag":
				node.tags[subtag.attrib["k"]] = subtag.attrib["v"]
		# Save to the osm obect
		osm.nodes[nodeid] = node
	elif tag.tag == "way":
		wayid = int(attrib["id"]);
		way = Way(wayid, int(attrib.get("version") or 1))
		for subtag in tag:
			if subtag.tag == "nd":
				if subtag.attrib.get("ref"):
					way.nodes.append(int(subtag.attrib["ref"]))
			if subtag.tag == "tag":
				way.tags[subtag.attrib["k"]] = subtag.attrib["v"] 
		osm.ways[wayid] = way
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

	for tag in xml:
		try:
			load_osm_export_tag(tag, osm)
		except KeyError as e:
			print("Missing values in tag:", e)
		except ValueError as e:
			print("invalid values in tag:", e)

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
		
	def fix_version(element):
		"""
		A lot of tools like jsom complane about a version number of zero
		"""
		if int(element.attrib["version"]) == 0:
			element.attrib["version"] = str(1)

	def remap_and_import_node(node, osm):
		fix_version(node)
		oldid = int(element.attrib["id"])
		# allocate and remap new id if needed
		newid = oldid
		if oldid < 0:
			newid = allocate_id(osm)
			element.attrib["id"] = str(newid)
		node_idmap[oldid] = newid

		load_osm_export_tag(element, osm)
		
	def remap_and_import_way(way, osm):
		fix_version(way)
		oldid = int(element.attrib["id"])
		# allocate and remap new id if needed
		newid = oldid
		if oldid < 0:
			newid = allocate_id(osm)
			element.attrib["id"] = str(newid)
		way_idmap[oldid] = newid

		for subelement in element:
			if subelement.tag == "nd":
				if int(subelement.attrib["ref"]) < 0:
					subelement.attrib["ref"] = str(node_idmap[int(subelement.attrib["ref"])])
		load_osm_export_tag(element, osm)

	# For newly created or modified elements, rewrite ids and import
	# Creation is handled first as modfied ways may reference newly created nodes
	for tag in xml:
		if tag.tag == "create" :
			# Do it in this order to ensure all new node ids are known before importing ways
			for element in tag:
				if element.tag == "node":
					remap_and_import_node(element, osm)
			for element in tag:
				if element.tag == "way":
					remap_and_import_way(element, osm)
				
	for tag in xml:
		if tag.tag == "modify" :
			# Do it in this order to ensure all new node ids are known before importing ways
			for element in tag:
				if element.tag == "node":
					remap_and_import_node(element, osm)
			for element in tag:
				if element.tag == "way":
					remap_and_import_way(element, osm)
	for tag in xml:
		if tag.tag == "delete":
			for element in tag:
				if element.tag == "node":
					nodeid = int(element.attrib["id"])
					node_idmap[nodeid] = None
					del osm.nodes[nodeid]
			for element in tag:
				if element.tag == "way":
					wayid = int(element.attrib["id"])
					way_idmap[nodeid] = None
					del osm.ways[wayid]
	root = ET.Element("diffResult")
	root.attrib["generator"] = "miniOSM"
	root.attrib["version"] = "0.6"
	for oldid in node_idmap.keys():
		xml_node = ET.SubElement(root, "node")
		xml_node.attrib["old_id"] = str(oldid)
		if node_idmap.get(oldid) and node_idmap[oldid]:
			xml_node.attrib["new_id"] = str(node_idmap[oldid])
			xml_node.attrib["new_version"] = str(osm.nodes[node_idmap[oldid]].version)
	for oldid in way_idmap.keys():
		xml_node = ET.SubElement(root, "way")
		xml_node.attrib["old_id"] = str(oldid)
		if way_idmap.get(oldid) and way_idmap[oldid]:
			xml_node.attrib["new_id"] = str(way_idmap[oldid])
			xml_node.attrib["new_version"] = str(osm.ways[way_idmap[oldid]].version)
	
	return root

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
		xml_node.attrib = {
			"id": str(node.nodeid),
			"lat": str(node.lat),
			"lon": str(node.lon),
			"version": str(node.version)
		}
		for key in node.tags.keys():
			xml_tag = ET.SubElement(xml_node, "tag")
			xml_tag.attrib = {
				"k": key,
				"v": node.tags[key]
			}
	
	for way in osm.ways.values():
		xml_way = ET.SubElement(root, "way")
		xml_way.attrib = {
			"id": str(way.wayid),
			"version": str(way.version),
		}
		for nodeid in way.nodes:
			xml_nd = ET.SubElement(xml_way, "nd")
			xml_nd.attrib = {"ref": str(nodeid)}
			
		for key in way.tags.keys():
			xml_tag = ET.SubElement(xml_way, "tag")
			xml_tag.attrib = {
				"k": key,
				"v": way.tags[key]
			}
	
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
			matching.nodes[node.nodeid] = node

	# Ways should be included if they have at least one node inside of the bounding obx
	included_ways = set()
	for way in osm.ways.values():
		for nodeid in way.nodes:
			if nodeid in matching.nodes:
				included_ways.add(way)
		
	for way in included_ways:	
		matching.ways[way.wayid] = way
		# inlude all nodes in the included way
		for nodeid in way.nodes:
			matching.nodes[nodeid] = osm.nodes[nodeid]
	
	return matching


def normalize_path(path):
	if path.startswith("/0.6"):
		path = path.removeprefix("/0.6")
	if path.startswith("/api"):
		path = path.removeprefix("/api")
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
			print("Unhandled GET request:", self.path)

	def do_PUT(self):
		if not self.server.write_file:
			self.send_response(403)
			return
		path = normalize_path(self.path)
		if (path == "/changeset/create"):
			# Request to create a changeset, respond with a dummy id of 0
			file = receive_file(self.rfile, self.headers);

			changeset_id = b"0"
			self.send_response(200)
			self.send_header("Content-type", "text/plain")
			self.send_header("Content-Length", len(changeset_id))
			self.end_headers()
			self.wfile.write(changeset_id)
		if (path == "/changeset/0/close"):
			# Close the dummy changeset
			self.send_response(200)
			self.send_header("Content-type", "text/plain")
			self.send_header("Content-Length", 0)
			self.end_headers()
		else:
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
			# Tell client things went right
			result = ET.tostring(result)
			self.send_response(200)
			self.send_header("Content-type", "application/xml")
			self.send_header("Content-Length", len(result))
			self.end_headers()
			self.wfile.write(result)

		else:
			print("Unhandled PUT request:", self.path)




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
