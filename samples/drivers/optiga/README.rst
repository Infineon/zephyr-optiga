.. _trustx:

OPTIGA Trust X: Hardware Security Controller
######################

Overview
********

This sample demonstrates a signature generation/verification using the device
specific key in the OPTIGA Trust X and generating an ECDSA key pair on the chip.

Dependencies
************

The example assumes you are using the nRF Connect SDK as installed by this
tutorial: https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/getting_started.html

It is also possible to build the example according to the standard Zephyr build
procedure, but this is untested.

Hardware
********

Connect an OPTIGA Trust X to the Arduino I2C interface of the board.
Alternatively it is possible to use the Shield2Go Adapter board and a Trust X
2Go board in Slot 1.


Building and Running
********************

In SEGGER Embedded Studio Nordic Edition V4.20a load the project using
"File -> Open nRF Connect SDK Project". For "CMakeLists.txt" insert
"zephyr/samples/drivers/optiga/CMakeLists.txt" and for "Board Directory" insert
"zephyr/boards/arm/nrf52840_pca10056". The rest should be filled out
automatically.

When building the example without SEGGER Embedded Studio, the output can be
received using the J-Link RTT Client.
