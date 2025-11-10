# Software Supply Chain HW Description
To build this project I downloaded the template from
github.com/mayank-ramnani/python-rekor-monitor-template
and then filled in the missing areas.
This project essentially tests multiple aspects of both
cosign and rekor transparency log by making sure that an
example artifact was signed succesfully and that its
signature was uploaded succesfully to the rekor
transparency log.
# Usage Instructions
To use the project one only needs to first make their
own artifact, it can be anything but I'll use artifact.md
in the instructions. It must then be signed with the command
"cosign sign-blod artifact.md --bundle artifact.bundle".
Now to use the project you just need to enter "python
main.py" along with the appropriate command afterwards
for the action you are doing. For example, "python main.py 
-c" would get the latest entry from the rekor transparency log.
# Installation instructions
To run the project itself, only cosign and python need
to be installed.