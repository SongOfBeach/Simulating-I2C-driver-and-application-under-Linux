#ifndef _YZYC_MAIN_H_
#define _YZYC_MAIN_H_

typedef int          BOOL;

typedef signed char                 S8;
typedef unsigned char               U8;
typedef signed short                S16;
typedef unsigned short              U16;
typedef signed int                  S32;
typedef unsigned int                U32;

typedef char*                       LPSTR;
typedef const char*                 LPCSTR;

#ifndef	TRUE
#define	TRUE 	1
#endif

#ifndef	FALSE
#define	FALSE 	0
#endif

#define	FAILURE -1
#define	SUCCESS 1

#define HTONL(x)	x
#define HTONS(x)	x
#define NTOHS(x)	HTONS(x)
#define NTOHL(x)	HTONL(x)


#define IO_CONTRAL			'i'	
#define IOCTL_IO_WRITE_L	_IOW(IO_CONTRAL,0,int)
#define IOCTL_IO_WRITE_H	_IOW(IO_CONTRAL,1,int)
#define IOCTL_IO_TEST		_IOW(IO_CONTRAL,2,int)

#define IO_CONTRAL_K			'k'	
#define IOCTL_IO_Load		_IOW(IO_CONTRAL_K,1,int)
#define IOCTL_IO_Normal	_IOW(IO_CONTRAL_K,2,int)
#define IOCTL_IO_Error		_IOW(IO_CONTRAL_K,3,int)

#endif /* _YZYC_MAIN_H_ */

