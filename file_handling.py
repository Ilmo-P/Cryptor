import os
import zipfile as zf

def find_targets(file_path:str, extension:str = '') -> tuple[list,list]:
    """Searches the file_path recursively for folders and files. Optionally the file extension to search for can be defined. The function will have no problems if the path leads straight to a file.
    
    Args:
        ``file_path``: The path to a directory which to scan for files and other directories.
        ``extension``: The file extension to look for. e.g. '.txt'
        
    Returns:
        ``[directory_list, file_list]``: A tuple that contains the directories and files found within the path."""
    directory_list = []
    file_list = []
    if os.path.isfile(file_path):
        file_list.append(file_path)
        return directory_list, file_list
    
    for root, dirs, files in os.walk(file_path, topdown=False):        
        lst = []

        for dir in dirs:
            dirpath = os.path.join(root,dir)
            if not has_full_permissions(dirpath):
                continue
            directory_list.append(dirpath)

        for file in files:
            ext = os.path.splitext(file)[1]
            filepath = os.path.join(root,file)
            if not has_full_permissions(filepath):
                continue
            if extension == '':
                ext = extension
            if ext == extension:
                lst.append(filepath)
        
        file_list.extend(lst)

    return directory_list, file_list

def zip_files(file_list:list) -> list:
    """Takes a list of file paths, zips them and deletes the original file. Files in the same folder will be put into single zip.

    Args:
        ``file_list``: A list of paths to files that need to be zipped.
    
    Returns:
        ``zipped_list``: Contains a list of paths to zip files that the function has created."""
    zipped_list = []
    for file_path in file_list:
        try:
            if is_enc(file_path) or is_zip(file_path):
                continue
            
            file_dir = os.path.dirname(file_path)
            dir_name = os.path.split(file_dir)[1]
            zip_name = dir_name + '.zip'
            zip_path = os.path.join(file_dir,zip_name)
            with zf.ZipFile(zip_path, 'a') as zip_object:
                zip_object.write(file_path, arcname=os.path.basename(file_path))
                os.remove(file_path)

            if zip_path in zipped_list:
                continue
            zipped_list.append(zip_path)

        except Exception as e:
            print(f"Zipping error. {e}")
    return zipped_list

def unzip_files(zip_paths:list):
    """Takes a list of paths containing zip files, extracts all the files and removes the zip.
    
    Args:
        ``zip_paths``: A list of paths to zip files that need to be unzipped."""
    for zip_path in zip_paths:
        try:
            if not zf.is_zipfile(zip_path) or not is_zip(zip_path):
                raise ValueError(f"Not a valid zip file: {zip_path}")
            
            directory = os.path.dirname(zip_path)
            with zf.ZipFile(zip_path, 'r') as zip_object:
                zip_object.extractall(directory)
            os.remove(zip_path)

        except Exception as e:
            print(f"Unzipping error. {e}")

def is_zip(file_path:str):
    """Uses the os module to determine if the file is a zip."""
    return os.path.splitext(file_path)[1].lower() == '.zip'

def is_enc(file_path:str):
    """Uses the os module to determine if the file is .enc format."""
    return os.path.splitext(file_path)[1].lower() == '.enc'

def has_full_permissions(file_path:str) -> bool:
    """Checks if the file or directory at file_path has read, write and execute permissions. Return True or False."""
    return os.access(file_path, os.R_OK | os.W_OK | os.X_OK)

