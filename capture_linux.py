import subprocess

def capture_linux():
    try:
        subprocess.run(
            "tcpdump -i any -nn -tttt -c 300 > packets.txt",
            shell=True,
            check=True
        )
        return True, "Packet capture completed (Linux)"

    except subprocess.CalledProcessError:
        return False, "tcpdump failed. Run Flask with sudo."
