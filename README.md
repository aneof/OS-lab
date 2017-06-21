# OS-lab
Projects done for Operating Systems lab course

'sensor chrdev driver' is an implementation of a character device driver for a number of sensors communicating with the personal computer
The assignment issued was coding the file "lunix-chrdev.c"

'virtIO crypto plus sockets' is an implementation of a cryptographic device for a Virtual Machine using the virtio (split driver model) standard. The virtualization platform used is QEMU. The file "virtio-crypto/qemu/hw/char/virtio-crypto.c" is the backend driver and the file "virtio-crypto/guest/crypto-chrdev.c" is the frontend driver which were both personally written as part of the assignment.
The project also included coding the necessary files for the implementation of an encrypted chat service using the BSD Sockets API as a method of testing the cryptographic device ("sockets/...").
