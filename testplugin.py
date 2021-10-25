from typing import List, Iterable, Tuple
from volatility3.framework import renderers, interfaces
from volatility3.framework.renderers import format_hints
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist, vadyarascan, memmap
import struct, binascii, pefile, peutils



class TestPlugin(plugins.PluginInterface):
	_required_framework_version = (2, 0, 0)
	_version = (1, 0, 0)
	
	@classmethod
	def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
		return [
			requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel', architectures = ["Intel32", "Intel64"]),
			requirements.BooleanRequirement(name = "wide", description = "Match wide (unicode) strings", default = False, optional = True),
			requirements.StringRequirement(name = "yara_rules", description = "Yara rules (as a string)", optional = True),
			requirements.URIRequirement(name = "yara_file", description = "Yara rules (as a file)", optional = True),
			requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
			requirements.VersionRequirement(name = 'yarascanner', component = yarascan.YaraScanner, version = (2, 0, 0)),
			requirements.ListRequirement(name = 'pid', element_type = int, description = "Process IDs to include (all other processes are excluded)", optional = True),
			requirements.BooleanRequirement(name = 'dump', description = "Extract listed memory segments", default = True, optional = True)
		]
	
	#analysis of memdump file
	def AnalyzeBeacon(self, dump_file):
		
		#dictionary of beacon_id : beacon_type
		beacon_types = {
		    0: 'windows-beacon_http-reverse_http',
		    1: 'windows-beacon_dns-reverse_http',
		    2: 'windows-beacon_smb-bind_pipz',
		    8: 'windows-beacon_https-reverse_https',
		    16: 'windows-beacon_tcp-bind_tcp'
		}

		#convert bytes to string
		def bytes2string(bytes):
		    return ''.join([chr(byte) for byte in bytes])

		#convert string to bytes
		def string2bytes(string):
		    return bytes([ord(x) for x in string])
		
		#XOR function for de-obfuscation of beacon
		def XOR(data, key):
		    data = bytes2string(data)
		    key = bytes2string(key)
		    return string2bytes(''.join(chr(ord(data[i]) ^ ord(key[i % len(key)])) for i in range(len(data))))

		#open the memdump file in binary mode
		binFile = open(dump_file, 'rb')
		data = binFile.read()
		binFile.close()

		#find pattern of cobalt beacon header to obtain offset
		offset = data.find(b'././.,',0)

		#length of cobalt config is 10000
		data = data[offset:offset+0x10000]

		#de-obfuscate data before analysis
		data = XOR(data, b'.')

		#list to store results of analysis
		result = []


		
		beacon_id = struct.unpack('>H', data[6:8])[0]
		result.append(["Beacon Type", beacon_types[beacon_id]])

		port_number = struct.unpack('>H', data[14:16])[0]
		result.append(["Remote Port Number", str(port_number)])

		beacon_connect_interval = struct.unpack('>I', data[22:26])[0]
		#in milliseconds
		result.append(["Connection Interval", str(beacon_connect_interval)])

		#in milliseconds
		beacon_jitter = struct.unpack('>H', data[42:44])[0]
		result.append(["Connection Jitter", str(beacon_jitter)])

		beacon_key = binascii.b2a_hex(data[50:306]).decode()
		result.append(["Beacon Key", beacon_key])

		C2_IP = data[312:327]
		result.append(["Remote IP", bytes2string(C2_IP)])

		C2_URI = data[328:568]
		result.append(["Server-URI", bytes2string(C2_URI)])
		return result
	
	
	def _generator(self, dumps):
		for dump in dumps:
			result = self.AnalyzeBeacon(dump)
			for (a, b) in result:
				yield 0, (a,b)
		
		
        
	def run(self):

		kernel = self.context.modules[self.config['kernel']]		
		filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
		rules = yarascan.YaraScan.process_yara_options(dict(self.config))
		
		hits = []
		dumpfiles = []
		
		for task in pslist.PsList.list_processes(self.context, layer_name=kernel.layer_name, symbol_table=kernel.symbol_table_name, filter_func = filter_func):
			layer_name = task.add_process_layer()
			layer = self.context.layers[layer_name]
			for each in layer.scan(context = self.context, scanner = yarascan.YaraScanner(rules = rules), sections = vadyarascan.VadYaraScan.get_vad_maps(task)):
				if task not in hits:
					hits.append(task)
		for a,b in memmap.Memmap._generator(self, hits):
			if (b[4] not in dumpfiles):
				dumpfiles.append(b[4])
		


		return renderers.TreeGrid([("Field", str), ("Value", str)], self._generator(dumpfiles))