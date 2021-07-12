#ifndef SYD_RC_GETFLAGS_H
#define SYD_RC_GETFLAGS_H

#define	NFLAG	128
#define	NCMDLINE	512
extern char **flag[NFLAG];
extern char cmdline[NCMDLINE+1];
extern char *cmdname;
extern char *flagset[];
int getflags(int, char*[], char*, int);

#endif /* !SYD_RC_GETFLAGS_H */
