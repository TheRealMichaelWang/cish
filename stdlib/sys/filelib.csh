global readonly int file_lib_offset = foreign[19]("stdlib/native/cish-native-stdlib.dll");  $loads the filelib dll library
if(file_lib_offset < 0)
 	abort; $abort if unable to load filelib dll

proc file_exists(array<char> file_path) {
	foreign[file_lib_offset](file_path); $selects a file
	bool toret = foreign[file_lib_offset + 3];
	foreign[file_lib_offset + 2];
	return toret;
}

proc file_create(array<char> file_path) {
	foreign[file_lib_offset](file_path); $selects a file
	if(foreign[file_lib_offset + 3]) {$check if file exists
		foreign[file_lib_offset + 2]; $closes the selected file
		return false; $no file was created
	}
	else {
		foreign[file_lib_offset + 4]; $creates a file
		foreign[file_lib_offset + 2]; $closes the selected file
		return true;
	}
}

proc file_write_bytes(array<char> file_path, array<int> bytes) {
	foreign[file_lib_offset](file_path); 
	if(foreign[file_lib_offset + 3]) {
		foreign[file_lib_offset + 6](bytes);
		return true;
	}
	return false;
}

proc file_write_text(array<char> file_path, array<char> contents) {
	foreign[file_lib_offset](file_path); $select file
	if(foreign[file_lib_offset + 3]){ $check if file exists
		foreign[file_lib_offset + 7](contents); $write contents
		foreign[file_lib_offset + 2]; $closes the selected file
		return true;
	}
	foreign[file_lib_offset + 2]; $closes the selected file
	return false;
}

proc file_read_text(array<char> file_path) return array<char> {
	foreign[file_lib_offset](file_path); $select
	return foreign[file_lib_offset + 5](true); $read characters from file
}

proc file_read_bytes(array<char> file_path) return array<int> {
	foreign[file_lib_offset](file_path); $select
	return foreign[file_lib_offset + 5](false); $read bytes from file
}