.. _trustm:

Infineon OPTIGA Trust M: Hardware Security Controller
######################

Overview
********

This sample demonstrates cryptographic operations using the
Infineon OPTIGA Trust M.

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

		*** Booting Zephyr OS build v2.3.0-rc1-243-g329b8ebbfd25  ***
		[00:00:01.257,324] <inf> main: Hello OPTIGA
		[00:00:01.257,385] <inf> main: Found Trust M device
		[00:00:01.257,415] <inf> main: ifx_optiga_trust_init res: 0, took 0 ms
		[00:00:01.287,597] <inf> main: ifx_optiga_data_get res: 0, took 30 ms
		[00:00:01.287,628] <inf> main: Co-processor UID:
		cd 16 33 82 01 00 1c 00  05 00 00 0a 09 1b 5c 00 |..3..... ......\.
		07 00 62 00 ad 80 10 10  71 08 09                |..b..... q..
		[00:00:01.397,705] <inf> main: ifx_optiga_data_get res: 0, took 110 ms
		[00:00:01.397,827] <inf> main: Full Certificate:
		c0 01 e2 00 01 df 00 01  dc 30 82 01 d8 30 82 01 |........ .0...0..
		7e a0 03 02 01 02 02 04  21 28 8c 3c 30 0a 06 08 |~....... !(.<0...
		2a 86 48 ce 3d 04 03 02  30 72 31 0b 30 09 06 03 |*.H.=... 0r1.0...
		55 04 06 13 02 44 45 31  21 30 1f 06 03 55 04 0a |U....DE1 !0...U..
		0c 18 49 6e 66 69 6e 65  6f 6e 20 54 65 63 68 6e |..Infine on Techn
		6f 6c 6f 67 69 65 73 20  41 47 31 13 30 11 06 03 |ologies  AG1.0...
		55 04 0b 0c 0a 4f 50 54  49 47 41 28 54 4d 29 31 |U....OPT IGA(TM)1
		2b 30 29 06 03 55 04 03  0c 22 49 6e 66 69 6e 65 |+0)..U.. ."Infine
		6f 6e 20 4f 50 54 49 47  41 28 54 4d 29 20 54 72 |on OPTIG A(TM) Tr
		75 73 74 20 4d 20 43 41  20 31 30 31 30 1e 17 0d |ust M CA  1010...
		31 39 30 36 31 38 30 36  33 30 31 34 5a 17 0d 33 |19061806 3014Z..3
		39 30 36 31 38 30 36 33  30 31 34 5a 30 1c 31 1a |90618063 014Z0.1.
		30 18 06 03 55 04 03 0c  11 49 6e 66 69 6e 65 6f |0...U... .Infineo
		6e 20 49 6f 54 20 4e 6f  64 65 30 59 30 13 06 07 |n IoT No de0Y0...
		2a 86 48 ce 3d 02 01 06  08 2a 86 48 ce 3d 03 01 |*.H.=... .*.H.=..
		07 03 42 00 04 7d 76 21  20 19 88 ec 36 d3 39 3e |..B..}v!  ...6.9>
		5a 3a dd 16 ad 2c 66 57  80 40 70 2c 92 b1 6e 84 |Z:...,fW .@p,..n.
		da 98 38 0e bc e3 3b ae  37 76 53 68 3f f9 4d 0e |..8...;. 7vSh?.M.
		6b 81 86 da 52 8e f7 19  2d e6 1d 82 55 ee 67 79 |k...R... -...U.gy
		b5 84 68 e4 3f a3 58 30  56 30 0e 06 03 55 1d 0f |..h.?.X0 V0...U..
		01 01 ff 04 04 03 02 00  80 30 0c 06 03 55 1d 13 |........ .0...U..
		01 01 ff 04 02 30 00 30  15 06 03 55 1d 20 04 0e |.....0.0 ...U. ..
		30 0c 30 0a 06 08 2a 82  14 00 44 01 14 01 30 1f |0.0...*. ..D...0.
		06 03 55 1d 23 04 18 30  16 80 14 3c 30 8c 5c d5 |..U.#..0 ...<0.\.
		8a e8 a3 5d 32 80 e4 54  83 b2 ff cd 86 4d 23 30 |...]2..T .....M#0
		0a 06 08 2a 86 48 ce 3d  04 03 02 03 48 00 30 45 |...*.H.= ....H.0E
		02 21 00 fc e0 53 80 82  f1 f2 5b 83 0b 58 de f9 |.!...S.. ..[..X..
		d2 d5 00 e1 34 ea 11 47  56 6e 53 6c d8 df 77 d8 |....4..G VnSl..w.
		5a 4a 89 02 20 03 4e 95  2a 74 39 23 2a 0b 67 88 |ZJ.. .N. *t9#*.g.
		4c 53 1b cb f4 e1 6d 7f  db b0 b6 ad 73 8e 6c 0b |LS....m. ....s.l.
		bb ad 2d 2a f1                                   |..-*.
		
		...
		
		[00:00:11.396,026] <inf> main: Example finished


.. _Pinout: https://github.com/Infineon/Assets/blob/master/Pictures/optiga_trust_m_shield2go_pinout.png
