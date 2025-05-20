import os
import platform
import argparse

def get_structure(folder_path, indent=0, filter_folder=None, exclude_folders=None, exclude_extensions=None):
    if exclude_folders is None:
        exclude_folders = ['.git']
    if exclude_extensions is None:
        exclude_extensions = ['.svg']

    structure = ""
    items = os.listdir(folder_path)
    for index, item in enumerate(items):
        if item in exclude_folders:
            continue

        item_path = os.path.join(folder_path, item)
        is_last = index == len(items) - 1

        if os.path.isdir(item_path):
            if filter_folder and filter_folder not in item:
                continue

            structure += '    ' * (indent // 4)
            structure += '└── ' if is_last else '├── '
            structure += f'[DIR] {item}\n'

            structure += get_structure(item_path, indent + 4, filter_folder, exclude_folders, exclude_extensions)
        else:
            file_ext = os.path.splitext(item)[1].lower()
            if file_ext in exclude_extensions:
                continue

            structure += '    ' * (indent // 4)
            structure += ('└── ' if is_last else '├── ') + f'[FILE] {item}\n'

    return structure

def get_file_contents(folder_path, filter_folder=None, exclude_folders=None, exclude_extensions=None):
    if exclude_folders is None:
        exclude_folders = ['.git']
    if exclude_extensions is None:
        exclude_extensions = ['.svg']

    contents = ""
    for root, dirs, files in os.walk(folder_path):
        path_parts = os.path.normpath(root).split(os.sep)
        if any(part in exclude_folders for part in path_parts):
            continue

        if filter_folder and filter_folder not in root:
            continue

        for file in files:
            file_ext = os.path.splitext(file)[1].lower()
            if file_ext in exclude_extensions:
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    contents += f"\n{'-' * 40}\nFile: {file_path}\n{'-' * 40}\n{content}\n"
            except Exception as e:
                contents += f"\n[ERROR] Could not read {file_path}: {e}\n"

    return contents

def save_and_open(output, folder_path):
    output_dir = os.path.join(folder_path, 'output')
    os.makedirs(output_dir, exist_ok=True)

    filename = f"project_structure_{len(os.listdir(output_dir)) + 1}.txt"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(output)

    if platform.system() == 'Windows':
        os.startfile(filepath)
    elif platform.system() == 'Darwin':
        os.system(f'open "{filepath}"')
    else:
        os.system(f'xdg-open "{filepath}"')

    return filepath

def interactive_mode():
    folder_path = input("Enter the folder path: ").strip()
    filter_folder = input("Enter folder name to filter (leave empty to show all): ").strip() or None
    exclude_folders = input("Enter folders to exclude (comma-separated, default: .git): ").strip()
    exclude_folders = [f.strip() for f in exclude_folders.split(',')] if exclude_folders else ['.git']
    exclude_extensions = input("Enter file extensions to exclude (comma-separated, default: .svg): ").strip()
    exclude_extensions = [e.strip().lower() for e in exclude_extensions.split(',')] if exclude_extensions else ['.svg']
    return folder_path, filter_folder, exclude_folders, exclude_extensions

def main():
    parser = argparse.ArgumentParser(description="Project structure and file reader")
    parser.add_argument("-C", "--custom", nargs=3, metavar=("FOLDER", "EXCLUDE_FOLDERS", "EXCLUDE_EXTENSIONS"),
                        help="Custom mode. Format: folder_path 'folder1,folder2' '.log,.md'")
    parser.add_argument("-F", "--filter", help="Only include folders containing this name", default=None)

    args = parser.parse_args()

    if args.custom:
        folder_path = args.custom[0]
        exclude_folders = [f.strip() for f in args.custom[1].split(',')]
        exclude_extensions = [e.strip().lower() for e in args.custom[2].split(',')]
        filter_folder = args.filter
    else:
        folder_path, filter_folder, exclude_folders, exclude_extensions = interactive_mode()

    structure = get_structure(
        folder_path,
        filter_folder=filter_folder,
        exclude_folders=exclude_folders,
        exclude_extensions=exclude_extensions
    )

    contents = get_file_contents(
        folder_path,
        filter_folder=filter_folder,
        exclude_folders=exclude_folders,
        exclude_extensions=exclude_extensions
    )

    output = f"Folder Structure:\n{structure}\n\nFile Contents:{contents}"

    try:
        saved_path = save_and_open(output, folder_path)
        print(f"\n✅ Output saved to: {saved_path}")
    except Exception as e:
        print(f"\n❌ Error saving file: {e}")
        print("Here's the output:\n")
        print(output)

if __name__ == "__main__":
    main()
