.. _trustm:

Infineon OPTIGA Trust M: Hardware Security Controller
######################

Overview
********

This sample demonstrates using an Infineon OPTIGA Trust M for signature
generation and verification on the NIST P256 ECC curve and with RSA.
Additionally it shows how to enable the Shielded Connection feature and the
power management of the Trust M.

Hardware
********

Connect an OPTIGA Trust M Shield2Go (`Pinout`_) to the Arduino I2C interface of
your board. Additionally connect `VCC CTRL` with a GPIO pin of your board and
configure it as ``power-gpios`` in the ``app.overlay`` file. An example for the
Trust M Shield2Go on the MyIoT adapter board is provided.


Building and Running
********************

Build and flash this sample (for example, for the nrf52840dk_nrf52840 board) using
these commands:

.. zephyr-app-commands::
   :zephyr-app: samples/drivers/optiga
   :board: nrf52840dk_nrf52840
   :goals: flash
   :compact:

Sample Output
=============
To check output of this sample, any serial console program can be used.
For example ``PuTTY`` on COM4 with 115200 baud:

.. code-block:: console

	*** Booting Zephyr OS build zephyr-v2.3.0-638-g5ed33700d758  ***
	[00:00:03.990,722] <inf> main: Hello OPTIGA
	[00:00:03.990,783] <inf> main: Found Trust M device
	[00:00:03.990,814] <inf> main: optrust_init res: 0, took 0ms
	[00:00:04.018,188] <inf> main: optrust_data_get res: 0, took 28ms
	[00:00:04.018,218] <inf> main: Co-processor UID:
	cd 16 33 82 01 00 1c 00  05 00 00 0a 09 1b 5c 00 |..3..... ......\.
	07 00 62 00 ad 80 10 10  71 08                   |..b..... q.
	[00:00:04.052,154] <inf> main: set platform binding secret res: 0, took 34ms
	[00:00:04.179,382] <inf> main: optrust_shielded_connection_psk_start res: 0, took 127ms
	[00:00:04.261,566] <inf> main: optrust_ecc_gen_keys_oid res: 0, took 82ms
	[00:00:04.261,596] <inf> main: Public key:
	84 7f fd 6f db 42 a2 2b  da 88 11 10 ab 10 c1 fc |...o.B.+ ........
	ca ab 2f de bc 18 31 b2  24 a9 f1 bf a3 41 a7 1a |../...1. $....A..
	9c b0 24 4e 66 c7 f5 3d  10 6a 9e b0 a6 31 18 59 |..$Nf..= .j...1.Y
	32 3c 88 51 ca 8e 34 f9  18 a8 c7 bb 95 de cc 89 |2<.Q..4. ........
	
	...
	
	[00:00:10.263,092] <inf> main: The OPTIGA Trust M will turn off in a few seconds to save power (Power LED off)
	[00:00:20.263,214] <inf> main: The OPTIGA Trust M will automatically turn on, to execute the next command (Power LED on)
	[00:00:20.361,480] <inf> main: Examples finished



.. _Pinout: https://github.com/Infineon/Assets/blob/master/Pictures/optiga_trust_m_shield2go_pinout.png
