import os

def get_file_signature(file_path, num_bytes=8):
    with open(file_path, 'rb') as file:
        filesignature = file.read(num_bytes)
    return filesignature


def check_for_masqueraded(file_path):
    valid_signatures = {
        b'\xFF\xD8\xFF\xE0\x00\x10': 'JPEG',
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG',
        b'\x47\x49\x46\x37\x38\x39\x61': 'GIF',
        b'\x25\x50\x44\x46\x2D': 'PDF',
        b'\x50\x4B\x03\x04\x05\x06\x07\x08': 'ZIP',
        b'\xFF\xFE\xEF\xBB\xBF': 'TXT',
        b'\x49\x44\x33': 'MP3',
        b'\x50\x4B\x03\x04\x14\x00\x06\x00': 'DOCX',
        b'\xD4\xC3\xB2\xA1': 'PCAP',
        # can add more signatures if needed
    }

    file_signature = get_file_signature(file_path)

    for filesignature, file_type in valid_signatures.items():
        if file_signature.startswith(filesignature):
            return False
    return True


def list_masqueraded_files(folder_path):
    masqueraded_files = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)

            if check_for_masqueraded(file_path):
                masqueraded_files.append(file_path)

    return masqueraded_files


def main():
    folder_path = input("Enter the folder path: ")

    if os.path.exists(folder_path):
        masqueraded_files = list_masqueraded_files(folder_path)

        if masqueraded_files:
            print("Masqueraded files found:")
            for file_path in masqueraded_files:
                print(file_path)
        else:
            print("No masqueraded files found.")
    else:
        print("ERROR: Path not Found.")


if __name__ == "__main__":
    main()
