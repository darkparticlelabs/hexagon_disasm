#ifndef _ELFTYPES_H
#define	_ELFTYPES_H

#if !defined(__APPLE__)
//#include <sys/feature_tests.h>
#else /* is Apple Mac OS X */
/* NOTHING */ /* In lieu of Solaris <sys/feature_tests.h> */

#if defined(__LP64__)
#if !defined(_LP64)
#define _LP64 /* Solaris vs. Darwin */
#endif
#else
#if !defined(_ILP32)
#define _ILP32 /* Solaris vs. Darwin */
#endif
#endif

#if !defined(_LONGLONG_TYPE)
#define _LONGLONG_TYPE
#endif

#endif /* __APPLE__ */

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_LP64) || defined(_I32LPx)
typedef unsigned int		Elf32_Addr;
typedef unsigned short		Elf32_Half;
typedef unsigned int		Elf32_Off;
typedef int			Elf32_Sword;
typedef unsigned int		Elf32_Word;
#else
typedef unsigned long		Elf32_Addr;
typedef unsigned short		Elf32_Half;
typedef unsigned long		Elf32_Off;
typedef long			Elf32_Sword;
typedef unsigned long		Elf32_Word;
#endif

#if defined(_LP64)
typedef unsigned long		Elf64_Addr;
typedef unsigned short		Elf64_Half;
typedef unsigned long		Elf64_Off;
typedef int			Elf64_Sword;
typedef long			Elf64_Sxword;
typedef	unsigned int		Elf64_Word;
typedef	unsigned long		Elf64_Xword;
typedef unsigned long		Elf64_Lword;
typedef unsigned long		Elf32_Lword;
#elif defined(_LONGLONG_TYPE)
typedef unsigned long long	Elf64_Addr;
typedef unsigned short		Elf64_Half;
typedef unsigned long long	Elf64_Off;
typedef int			Elf64_Sword;
typedef long long		Elf64_Sxword;
typedef	unsigned int		Elf64_Word;
typedef	unsigned long long	Elf64_Xword;
typedef	unsigned long long	Elf64_Lword;
typedef unsigned long long	Elf32_Lword;
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ELFTYPES_H */