# SHELLGUARD
This is a simple tool which helps you protect your ELF binary.


# Usage
```python
python main.py <FILENAME>
```

# What does it do?
1. add a segment to store shellcode in ELF binary
2. copy a seccomp shellcode to the segment
2. hook a plt and jump to your shellcode