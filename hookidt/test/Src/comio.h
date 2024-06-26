/*
  Copyright notice
  ================
  
  Copyright (C) 2010
      Lorenzo  Martignoni <martignlo@gmail.com>
      Roberto  Paleari    <roberto.paleari@gmail.com>
      Aristide Fattori    <joystick@security.dico.unimi.it>
  
  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.
  
  HyperDbg is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with
  this program. If not, see <http://www.gnu.org/licenses/>.
  
*/

#ifndef _PILL_COMIO_H
#define _PILL_COMIO_H

#include <ntddk.h>

#define COM_PORT_IRQ                    0x004
#define COM_PORT_ADDRESS                0x3f8

/* COM level communication */
VOID  NTAPI ComInit(VOID);
VOID  NTAPI ComPrint(PUCHAR fmt, ...);
UCHAR NTAPI ComIsInitialized();

/* Hardware port level communication */
VOID  NTAPI PortInit(VOID);
VOID  NTAPI PortSendByte(UCHAR b);
UCHAR NTAPI PortRecvByte(VOID);

#endif	/* _PILL_COMIO_H */
