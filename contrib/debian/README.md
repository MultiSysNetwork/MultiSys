
Debian
====================
This directory contains files used to package multisysd/multisys-qt
for Debian-based Linux systems. If you compile multisysd/multisys-qt yourself, there are some useful files here.

## multisys: URI support ##


multisys-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install multisys-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your multisys-qt binary to `/usr/bin`
and the `../../share/pixmaps/multisys128.png` to `/usr/share/pixmaps`

multisys-qt.protocol (KDE)

