import os
import platform
import argparse


def normalize_excludes(raw_excludes):
    """
    ورودی کاربر مانند:
    ".log,.md,phpunit.xml,stylelintrc.json,TODO"
    
    خروجی:
      exclude_extensions = ['.log', '.md', '.xml', '.json']
      exclude_files      = ['phpunit.xml', 'stylelintrc.json', 'TODO']
    """

    exclude_extensions = []
    exclude_files = []

    for item in raw_excludes:
        item = item.strip()

        # پسوند مستقیم مثل .log
        if item.startswith('.') and item.count('.') == 1:
            exclude_extensions.append(item.lower())
            continue

        # فایل با پسوند مثل stylelintrc.json
        if '.' in item:
            ext = '.' + item.split('.')[-1].lower()
            exclude_extensions.append(ext)
            exclude_files.append(item)
            continue

        # فایل بدون پسوند (مثل TODO)
        exclude_files.append(item)

    return exclude_extensions, exclude_files


def get_structure(folder_path, indent=0, filter_folder=None, exclude_folders=None, exclude_files=None, exclude_extensions=None):
    structure = ""

    try:
        items = os.listdir(folder_path)
    except:
        return ""

    for index, item in enumerate(items):
        item_path = os.path.join(folder_path, item)
        is_last = index == len(items) - 1

        # حذف فولدرها
        if item in exclude_folders:
            continue

        # حذف فایل بر اساس نام دقیق
        if item in exclude_files:
            continue

        # حذف فایل بر اساس پسوند
        if any(item.lower().endswith(ext) for ext in exclude_extensions):
            continue

        # زیرفولدر
        if os.path.isdir(item_path):
            if filter_folder and filter_folder not in item:
                continue

            structure += '    ' * (indent // 4)
            structure += ('└── ' if is_last else '├── ') + f"[DIR] {item}\n"

            structure += get_structure(
                item_path,
                indent + 4,
                filter_folder,
                exclude_folders,
                exclude_files,
                exclude_extensions
            )
        else:
            structure += '    ' * (indent // 4)
            structure += ('└── ' if is_last else '├── ') + f"[FILE] {item}\n"

    return structure


def get_file_contents(folder_path, filter_folder=None, exclude_folders=None, exclude_files=None, exclude_extensions=None):
    contents = ""

    for root, dirs, files in os.walk(folder_path):
        path_parts = os.path.normpath(root).split(os.sep)

        # حذف فولدرهای غیرمجاز
        if any(part in exclude_folders for part in path_parts):
            continue

        if filter_folder and filter_folder not in root:
            continue

        for file in files:
            # حذف نام کامل
            if file in exclude_files:
                continue

            # حذف بر اساس پسوند
            if any(file.lower().endswith(ext) for ext in exclude_extensions):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    contents += f"\n{'-'*40}\nFile: {file_path}\n{'-'*40}\n{content}\n"
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


def main():
    parser = argparse.ArgumentParser(description="Project structure and file reader")

    parser.add_argument(
        "-C", "--custom",
        nargs=3,
        metavar=("FOLDER", "EXCLUDE_FOLDERS", "EXCLUDE_EXT_FILES"),
        help="Custom mode: folder_path 'folder1,folder2' '.log,.md,phpunit.xml'"
    )

    parser.add_argument("-F", "--filter", help="Filter folder name", default=None)

    args = parser.parse_args()

    if args.custom:
        folder_path = args.custom[0]

        exclude_folders = [f.strip() for f in args.custom[1].split(',') if f.strip()]
        raw_excludes = [e.strip() for e in args.custom[2].split(',') if e.strip()]

        exclude_extensions, exclude_files = normalize_excludes(raw_excludes)

        filter_folder = args.filter
    else:
        print("Interactive mode not supported in this version.")
        return

    structure = get_structure(folder_path, 0, filter_folder, exclude_folders, exclude_files, exclude_extensions)
    contents = get_file_contents(folder_path, filter_folder, exclude_folders, exclude_files, exclude_extensions)

    output = f"Folder Structure:\n{structure}\n\nFile Contents:\n{contents}"

    saved_path = save_and_open(output, folder_path)
    print(f"\n✔ Output saved to: {saved_path}")


if __name__ == "__main__":
    main()
