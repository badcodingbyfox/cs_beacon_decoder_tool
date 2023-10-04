#!/usr/bin/env python
import os
import sys
import zlib
import string
import base64

#	Print Header
def print_header(phase):
	print('\n'+'#'*21)
	print('#'+' '*5+'Phase '+str(phase)+':'+' '*5+'#')
	print('#'*21+'\n')

#	Generic Output to file function
def out_to_file(string, file_name):
	f = open(file_name,'w')
	f.write(string)
	f.close()

#	Base64 Decode function
def out_to_string(encoded_string):
	decoded_string = base64.b64decode(encoded_string)
	return decoded_string

def bruteforce_xor_key(first_byte):
	for i in range(255):
		if first_byte[0]^ i == 0xFC:
			return i
	return None

#	Ingest code from Phase 01 file function
def code_ingester(file_name):
	cmd = open(file_name, 'r').read().rstrip()
	return cmd

#	Ingest code from Phase 03 output and extract base64 encoded shellcode
def shellcode_finder(file_name):
	with open (file_name, 'r') as script:
		for line in script.readlines():
			if 'FromBase64String("' in line:
				return str(line.split('"')[1])
			elif "FromBase64String(''" in line:
				return str(line.split("''")[1])
			elif "FromBase64String('" in line:
				return str(line.split("'")[1])				

#	Phase 02 extraction process. Iterate byte by byte and decode the base64 encoded string and write output to file
def decode_phase_02(string, file_name):
	print_header('2')
	if os.path.isfile(file_name):
		print('\nThis code block has already been extracted.\n\tNOTE: See "'+file_name+'" file.\n')
	else:
		print('Decrypted command:\n')
		decoded_cmd = out_to_string(string)
		shell_code = ''
		for c in bytearray(decoded_cmd):
			if c != 0:
				shell_code += chr(c)
		out_to_file(shell_code, file_name)
	print('-'*21+'\n'*2+code_ingester(file_name)+'\n'*2+'-'*21)

#	Phase 03 extraction process. Iterate byte by byte and decode the base64 encoded string and then decompress the output and write to file
def decode_phase_03(file_name):
	print_header('3')
	string = shellcode_finder('phase_02.txt')
	if os.path.isfile(file_name):
		print('\nThis code block has already been extracted.\n\tNOTE: See "'+file_name+'" file.\n')
	else:
		print('Compressed Base64 string found.\n\nDecompressed command:')
		decoded_cmd = zlib.decompress(out_to_string(string), 16+zlib.MAX_WBITS)
		shell_code = ''
		for c in bytearray(decoded_cmd):
			shell_code += (chr(c))
		out_to_file(shell_code, file_name)
	print('-'*21+'\n'*2+code_ingester(file_name)+'\n'*2+'-'*21)

#	Decode base64 shellcode string from Phase 03, XOR the results and then write decrypted shellcode to bin file
def decode_phase_04(file_name):
	print_header('4')
	if os.path.isfile(file_name):
		print('\nThis code block has already been extracted.\n\tNOTE: See "'+file_name+'" file.\n')
	else:
		print('Extracting shellcode.')
		string = shellcode_finder('phase_03.txt')
		byte_array = out_to_string(string)
		xor_key = bruteforce_xor_key(byte_array)
		print('\nXOR Key: '+str(xor_key))
		print('-'*21+'\n')
		shell_code = ''
		for c in bytearray(byte_array):
			shell_code += (chr(c^xor_key))
		out_to_file(shell_code, file_name)
	print('Extracted Shellcode:\n')
	print('-'*21+'\n'*2+code_ingester(file_name)+'\n'*2+'-'*21)

def strings(filename, min=4):
	with open(filename, errors='ignore') as f:
		result = ''
		for c in f.read():
			if c in string.printable:
				result += c
				continue
			if len(result) >= min:
				yield result
			result = ''
		if len(result) >= min:
			yield result

def print_strings_from_shellcode(filename):
	print('Printing strings found in {}'.format(filename)+':\n'+'-'*21+'\n')
	for extracted_string in strings(filename):
		print(extracted_string)
	print('\n'+'-'*21+'\n')

def process_code():
#	Identify Compression String:
	compression_string = 'IO.Compression.GzipStream'

#	Shellcode Identification String
	shellcode_byte_array = 'System.Runtime.InteropServices.Marshal'

#	Initial Base64 code string
	string = code_ingester('phase_01.txt')

	print_header('1')
	print('-'*21+'\n'*2+string+'\n'*2+'-'*21)
	decode_phase_02(string, 'phase_02.txt')
	if compression_string in code_ingester('phase_02.txt'):
		decode_phase_03('phase_03.txt')
		if shellcode_byte_array in code_ingester('phase_03.txt'):
			decode_phase_04('phase_04.bin')
			strings('phase_04.bin', min=4)
			print_strings_from_shellcode('phase_04.bin')
	else:
		print('-'*21+'\n'+out_to_string(string).decode("utf-8")+'\n'+'-'*21)

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print('Invalid syntax.\n-h, Help\n-f, input file\n-s, input string')
		exit()
	switch = sys.argv[1]
	while True:
		if switch == '-h':
			print('Available Options:\n-h, Help\n-f, input file\n-s, input string')
			exit()
		elif switch == '-f':
			input_file = sys.argv[2]
			if os.path.isfile(input_file):
				out_to_file(code_ingester(input_file), 'phase_01.txt')
				break
			else:
				print('File not found!')
				exit()
		elif switch == '-s':
			out_to_file(sys.argv[2], 'phase_01.txt')
			break
		else:
			print('Invalid syntax.\n-h, Help\n-f, input file\n-s, input string')
			exit()
	process_code()
