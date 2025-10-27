/* gcc -Wall -O3 -o xfer xfer.c */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define SPRE 2
#define SRUN 1
#define SQUE 0
#define SFIN -1

#define ZERO 0
#define MSEC 3
#define BLEN 10
#define DLEN 15
#define DSIZ 90
#define NUMB 5000
#define SIZE 9000
#define TLEN 75000

#define NOWS time(NULL)

struct mapp
{
	char prot[BLEN];
	int port, secs;
};

struct argp
{
	int locl, lprt, blen;
	char *prot, *ladr, *bind, *file, *envr;
	struct sockaddr_in bnds[BLEN];
	struct mapp timo[TLEN];
};

struct conp
{
	int stat, dprt, stop;
	int conn, remo, expr;
	char srcs[SIZE], port[SIZE], dsts[SIZE];
	char *flag;
	int blen;
	unsigned char buff[SIZE];
	time_t last, logs[2];
	struct sockaddr_in addr, dest;
	pthread_t thrd;
	struct argp *argv;
};

char TOBJ[SIZE];

int DIDX = 0;
char DOBJ[DLEN][DSIZ];
pthread_mutex_t LOCK = PTHREAD_MUTEX_INITIALIZER;

void sige(int s)
{
	printf("EXIT\n");
	exit(0);
}

void sigp(int s)
{
	printf("PIPE\n");
}

void sigs()
{
	signal(SIGINT, sige);
	signal(SIGPIPE, SIG_IGN);
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);
}

char *date()
{
	time_t secs = NOWS;
	struct tm *info = localtime(&secs);
	int modi = ((secs % (DLEN - 1)) + 1);
	if (modi != DIDX)
	{
		pthread_mutex_lock(&LOCK);
		bzero(DOBJ[modi], DSIZ);
		strftime(DOBJ[modi], 50, "%Y-%m-%d_%H:%M:%S", info);
		DIDX = modi;
		pthread_mutex_unlock(&LOCK);
	}
	return DOBJ[DIDX];
}

int gtim(struct mapp *list, char *prot, int port)
{
	int defa = 0, valu = 0;
	for (int x = 0; x < TLEN; ++x)
	{
		if (strcmp(list[x].prot, prot) == 0)
		{
			if (list[x].port == 0)
			{
				defa = list[x].secs;
			}
			if (list[x].port == port)
			{
				valu = list[x].secs;
			}
		}
	}
	if (valu > 0) { return valu; }
	return defa;
}

int safe(char *strs)
{
	if (!strs) { return 0; }
	int port = atoi(strs);
	if ((port < 0x0000) || (0xffff < port)) { return 0; }
	return port;
}

char *trim(char *strs)
{
	while (*strs == ' ')
	{
		++strs;
		if (*strs == '\0') { break; }
	}
	return strs;
}

void catn(char *s, int a, int b)
{
	char buff[96];
	bzero(buff, 96);
	snprintf(buff, 64, "%s:%d=%d, ", s, a, b);
	int i = 0;
	int l = strlen(TOBJ);
	int n = strlen(buff);
	while ((i < n) && (l < (SIZE - 11)))
	{
		TOBJ[l] = buff[i]; ++i; ++l;
	}
}

void parc(struct mapp *outp, char *inpt, char *tnum, char *pstr)
{
	while (1)
	{
		char *pntr = strchr(inpt, ',');
		if (pntr) { *pntr = 0; ++pntr; }
		int tval = atoi(tnum);
		int pval = safe(inpt);
		pstr = trim(pstr);
		for (int x = 0; x < TLEN; ++x)
		{
			if (outp[x].prot[0] == 0)
			{
				strncpy(outp[x].prot, pstr, BLEN - 5);
				outp[x].port = pval; outp[x].secs = tval;
				break;
			}
		}
		catn(pstr, pval, tval);
		if (!pntr || !(*pntr)) { break; }
		inpt = pntr;
	}
}

void parb(struct mapp *outp, char *inpt, char *tnum)
{
	while (1)
	{
		char *pntr = strchr(inpt, '/');
		if (pntr) { *pntr = 0; ++pntr; }
		if (!pntr || !(*pntr)) { break; }
		parc(outp, pntr, tnum, inpt);
		inpt = pntr;
	}
}

void para(struct mapp *outp, char *inpt)
{
	while (1)
	{
		char *pntr = strchr(inpt, '@');
		if (pntr) { *pntr = 0; ++pntr; }
		if (!pntr || !(*pntr)) { break; }
		parb(outp, inpt, pntr);
		inpt = pntr;
	}
}

void tims(struct mapp *outp, char *inpt)
{
	while (1)
	{
		char *pntr = strchr(inpt, ';');
		if (pntr) { *pntr = 0; ++pntr; }
		para(outp, inpt);
		if (!pntr || !(*pntr)) { break; }
		inpt = pntr;
	}
}

void uadr(char **pntr, int *port, char *inpt)
{
	char *temp = strchr(inpt, ':');
	*pntr = inpt; *port = 0;
	if (temp)
	{
		*temp = 0; ++temp;
		*pntr = inpt;
		*port = atoi(temp);
	}
}

void fins(int *sock)
{
	if (*sock > 1)
	{
		shutdown(*sock, SHUT_RDWR);
		close(*sock);
	}
	*sock = -1;
}

int rall(int sock, unsigned char *buff, int leng)
{
	if (leng < 1) { return -1; }
	return recv(sock, buff, leng, 0);
}

int sall(int sock, unsigned char *buff, int leng)
{
	int wlen;
	if (leng < 1) { return -1; }
	while (leng > 0)
	{
		wlen = send(sock, buff, leng, 0);
		if (wlen < 0) { return -2; }
		buff += wlen; leng -= wlen;
	}
	return 1;
}

void comd(char *path, char *addr, char *port, char *prot, char *buff, int leng)
{
	int link[2];
	if (pipe(link) < 0) { return; }
	pid_t pidn = fork();
	if (pidn == 0)
	{
		dup2(link[1], STDOUT_FILENO);
		close(link[0]); close(link[1]);
		execl(path, path, addr, port, prot, NULL);
	}
	else
	{
		close(link[1]);
		waitpid(pidn, NULL, 0);
		int rlen = read(link[0], buff, leng);
		if (rlen < 1) { /* no-op */ }
		close(link[0]);
	}
}

void *mgmt(void *argv)
{
	struct conp *cons = (struct conp *)argv;
	struct argp *args = cons->argv;

	int expr = 0, news = 15, udpx = 30, tcpx = 30000;
	int kind = (strcmp(args->prot, "udp") == 0) ? 1 : 2;
	time_t last = 0;

	while (1)
	{
		int alen = 0, blen = 0;
		time_t secs = NOWS;

		for (int x = 0; x < NUMB; ++x)
		{
			if (cons[x].stat == SQUE) { continue; }
			if (cons[x].stat == SPRE)
			{
				if ((kind != 0) && ((secs - cons[x].last) >= news))
				{
					cons[x].flag = "news"; cons[x].stop |= 16;
				}
			}
			if (cons[x].stat > SQUE)
			{
				if (cons[x].expr < 1)
				{
					expr = gtim(args->timo, args->prot, cons[x].dprt);
					if (expr == 0)
					{
						expr = (kind == 1) ? udpx : tcpx;
					}
					cons[x].expr = expr;
				}
				if ((kind == 1) && ((secs - cons[x].last) >= expr))
				{
					cons[x].flag = "udpx"; cons[x].stop |= 32;
				}
				if ((kind == 2) && ((secs - cons[x].last) >= expr))
				{
					cons[x].flag = "tcpx"; cons[x].stop |= 64;
				}
			}
			if ((cons[x].stat < SQUE) || (cons[x].stop > 0))
			{
				if ((cons[x].conn > 1) || (cons[x].remo > 1))
				{
					printf("%s INFO fins [%s:%s] * [%s:%d] [%s:%d:%d:%d] [%s:%d:%d]\n", date(), cons[x].srcs, cons[x].port, cons[x].dsts, cons[x].dprt, args->prot, cons[x].expr, cons[x].conn, cons[x].remo, cons[x].flag, cons[x].stat, cons[x].stop); fflush(stdout);
				}
				fins(&cons[x].remo);
				fins(&cons[x].conn);
				if (cons[x].stat == SFIN)
				{
					printf("%s INFO join [%s:%s] * [%s:%d] [%s:%d:%d:%d] [%s:%d:%d]\n", date(), cons[x].srcs, cons[x].port, cons[x].dsts, cons[x].dprt, args->prot, cons[x].expr, cons[x].conn, cons[x].remo, cons[x].flag, cons[x].stat, cons[x].stop); fflush(stdout);
					pthread_join(cons[x].thrd, NULL);
					bzero(&cons[x], sizeof(struct conp));
				}
				++blen;
			}
			else
			{
				++alen;
			}
		}

		if ((secs - last) >= (MSEC + MSEC))
		{
			printf("%s INFO mgmt [%d:%d]\n", date(), alen, blen); fflush(stdout);
			last = secs;
		}

		sleep(MSEC);
	}

	return NULL;
}

void *xfer(void *argv)
{
	struct conp *cons = (struct conp *)argv;
	struct argp *args = cons->argv;

	int bidx = (rand() % args->blen);
	int *port = &cons->dprt;
	char *dsts = cons->dsts;

	cons->flag = "*";
	bzero(cons->srcs, SIZE);
	inet_ntop(AF_INET, &(cons->addr.sin_addr), cons->srcs, INET_ADDRSTRLEN);
	bzero(cons->port, SIZE);
	snprintf(cons->port, SIZE - 11, "%d", ntohs(cons->addr.sin_port));
	bzero(cons->dsts, SIZE);
	comd(args->file, cons->srcs, cons->port, args->prot, cons->dsts, SIZE - 11);

	printf("%s INFO conn [%s:%s] ! [%s] [%s]\n", date(), cons->srcs, cons->port, cons->dsts, args->prot); fflush(stdout);

	bzero(&cons->dest, sizeof(struct sockaddr_in));

	if (strcmp(cons->dsts, "") == 0)
	{
		cons->flag = "dest"; cons->stop |= 1;
	}
	else
	{
		uadr(&dsts, port, cons->dsts);
		cons->dest.sin_family = AF_INET;
		cons->dest.sin_port = htons(*port);
		cons->dest.sin_addr.s_addr = inet_addr(dsts);

		if (strcmp(args->prot, "udp") == 0)
		{
			cons->remo = socket(AF_INET, SOCK_DGRAM, 0);
			if (bind(cons->remo, (struct sockaddr *)&args->bnds[bidx], sizeof(struct sockaddr_in)) < 0)
			{
				cons->flag = "bind"; cons->stop |= 2;
			}
			if (cons->blen > 0)
			{
				sendto(cons->remo, cons->buff, cons->blen, 0, (struct sockaddr *)&cons->dest, sizeof(struct sockaddr_in));
			}
		}
		else
		{
			cons->remo = socket(AF_INET, SOCK_STREAM, 0);
			if (bind(cons->remo, (struct sockaddr *)&args->bnds[bidx], sizeof(struct sockaddr_in)) < 0)
			{
				cons->flag = "bind"; cons->stop |= 4;
			}
			if (connect(cons->remo, (struct sockaddr *)&cons->dest, sizeof(struct sockaddr_in)) < 0)
			{
				cons->flag = "syns"; cons->stop |= 8;
			}
		}
	}

	int sels, dlen, slen;
	int kind = (strcmp(args->prot, "udp") == 0) ? 1 : 2;
	int maxf = (cons->conn > cons->remo) ? cons->conn : cons->remo;
	unsigned int clen, zlen = sizeof(struct sockaddr_in);
	unsigned char buff[SIZE];
	fd_set rfds;
	struct timeval tout;
	struct sockaddr_in cadr;
	struct sockaddr_in *cptr;

	cons->stat = SRUN;

	while (1)
	{
		if ((cons->stat != 1) || (cons->stop != 0)) { break; }

		FD_ZERO(&rfds);
		if (cons->conn > 1) { FD_SET(cons->conn, &rfds); }
		if (cons->remo > 1) { FD_SET(cons->remo, &rfds); }
		tout.tv_sec = 3;
		tout.tv_usec = 0;
		sels = select(maxf + 1, &rfds, NULL, NULL, &tout);
		if (sels < 0) { cons->flag = "sels"; break; }

		if ((cons->stat != 1) || (cons->stop != 0)) { break; }

		time_t secs = NOWS;

		if (FD_ISSET(cons->conn, &rfds))
		{
			if (kind == 1)
			{
				dlen = 0;
				/*dlen = pall(cons->conn, buff, SIZE);
				if (dlen < 1) { cons->flag = "read-conn"; break; }
				cptr = &cons->dest;
				slen = sendto(cons->remo, buff, dlen, 0, (struct sockaddr *)cptr, zlen);
				if (slen < 1) { cons->flag = "send-conn"; break; }*/
			}
			if (kind == 2)
			{
				dlen = rall(cons->conn, buff, SIZE);
				if (dlen < 1) { cons->flag = "read-conn"; break; }
				slen = sall(cons->remo, buff, dlen);
				if (slen < 1) { cons->flag = "send-conn"; break; }
			}
			cons->last = secs;
			if ((secs - cons->logs[0]) >= 3)
			{
				printf("%s INFO send [%s:%s] > [%s:%d] [%s:%d]\n", date(), cons->srcs, cons->port, cons->dsts, cons->dprt, args->prot, dlen); fflush(stdout);
				cons->logs[0] = secs;
			}
		}

		if (FD_ISSET(cons->remo, &rfds))
		{
			if (kind == 1)
			{
				clen = zlen;
				bzero(&cadr, clen);
				dlen = recvfrom(cons->remo, buff, SIZE, 0, (struct sockaddr *)&cadr, &clen);
				if (dlen < 1) { cons->flag = "read-remo"; break; }
				cptr = &cons->addr;
				slen = sendto(args->locl, buff, dlen, 0, (struct sockaddr *)cptr, zlen);
				if (slen < 1) { cons->flag = "send-remo"; break; }
			}
			if (kind == 2)
			{
				dlen = rall(cons->remo, buff, SIZE);
				if (dlen < 1) { cons->flag = "read-remo"; break; }
				slen = sall(cons->conn, buff, dlen);
				if (slen < 1) { cons->flag = "send-remo"; break; }
			}
			cons->last = secs;
			if ((secs - cons->logs[1]) >= 3)
			{
				printf("%s INFO recv [%s:%s] < [%s:%d] [%s:%d]\n", date(), cons->srcs, cons->port, cons->dsts, cons->dprt, args->prot, dlen); fflush(stdout);
				cons->logs[1] = secs;
			}
		}
	}

	printf("%s INFO stop [%s:%s] * [%s:%d] [%s][%d:%d]\n", date(), cons->srcs, cons->port, cons->dsts, cons->dprt, cons->flag, cons->stat, cons->stop); fflush(stdout);

	cons->stat = SFIN;

	return NULL;
}

void loop(struct argp *args)
{
	int dlen, wlen;
	unsigned int clen;
	unsigned char buff[SIZE];
	struct sockaddr_in cadr;
	pthread_t thrd;
	struct conp *cons = malloc(NUMB * sizeof(struct conp));

	for (int x = 0; x < NUMB; ++x)
	{
		bzero(&(cons[x]), sizeof(struct conp));
		cons[x].argv = args;
	}

	pthread_create(&thrd, NULL, mgmt, (void *)&cons[0]);

	while (1)
	{
		int indx = -1;
		clen = sizeof(struct sockaddr_in);
		bzero(&cadr, clen);

		if (strcmp(args->prot, "udp") == 0)
		{
			dlen = recvfrom(args->locl, buff, SIZE, 0, (struct sockaddr *)&cadr, &clen);
			if (dlen < 1) { break; }
			clen = sizeof(struct sockaddr_in);
			for (int x = 0; x < NUMB; ++x)
			{
				if ((cons[x].stat >= SRUN) && (memcmp(&cons[x].addr, &cadr, clen) == 0))
				{
					indx = (1 * (x + 11));
				}
				if ((cons[x].stat == SQUE) && (indx == -1))
				{
					indx = (-1 * (x + 11));
				}
			}
			if (indx < -1)
			{
				indx = ((indx * -1) - 11);
				cons[indx].blen = dlen;
				bcopy(buff, cons[indx].buff, dlen);
				bcopy(&cadr, &cons[indx].addr, clen);
				cons[indx].conn = ZERO;
				cons[indx].remo = ZERO;
				cons[indx].expr = ZERO;
				cons[indx].last = NOWS;
				cons[indx].stat = SPRE;
				cons[indx].argv = args;
				pthread_create(&cons[indx].thrd, NULL, xfer, (void *)&cons[indx]);
			}
			if (indx > -1)
			{
				indx = ((indx * 1) - 11);
				int sock = cons[indx].conn;
				if (sock > 1)
				{
					wlen = write(sock, buff, dlen);
					if (wlen < 0) { printf("%s WARN dlen [%s]\n", date(), args->prot); fflush(stdout); }
				}
			}
			if (indx == -1)
			{
				printf("%s WARN nofd [%s]\n", date(), args->prot); fflush(stdout);
			}
		}

		else
		{
			int conn = accept(args->locl, (struct sockaddr *)&cadr, &clen);
			if (conn < 1) { break; }
			clen = sizeof(struct sockaddr_in);
			for (int x = 0; x < NUMB; ++x)
			{
				if ((cons[x].stat == SQUE) && (indx == -1))
				{
					indx = x;
				}
			}
			if (indx > -1)
			{
				bcopy(&cadr, &cons[indx].addr, clen);
				cons[indx].conn = conn;
				cons[indx].remo = ZERO;
				cons[indx].expr = ZERO;
				cons[indx].last = NOWS;
				cons[indx].stat = SPRE;
				cons[indx].argv = args;
				pthread_create(&cons[indx].thrd, NULL, xfer, (void *)&cons[indx]);
			}
			if (indx == -1)
			{
				printf("%s WARN nofd [%s]\n", date(), args->prot); fflush(stdout);
				fins(&conn);
			}
		}
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_in ladr;
	struct argp args;

	bzero(&args, sizeof(struct argp));
	for (int x = 1; x < argc; ++x)
	{
		if ((strcmp(argv[x], "-p") == 0) && ((x + 1) < argc))
		{
			args.prot = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-l") == 0) && ((x + 1) < argc))
		{
			args.ladr = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-b") == 0) && ((x + 1) < argc))
		{
			args.bind = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-f") == 0) && ((x + 1) < argc))
		{
			args.file = strdup(argv[x + 1]);
		}
	}

	if (strcmp(args.prot, "udp") == 0)
	{
		args.locl = socket(AF_INET, SOCK_DGRAM, 0);
	}
	else
	{
		args.locl = socket(AF_INET, SOCK_STREAM, 0);
	}

	srand(NOWS);
	sigs();

	uadr(&args.ladr, &args.lprt, args.ladr);
	ladr.sin_family = AF_INET;
	ladr.sin_port = htons(args.lprt);
	ladr.sin_addr.s_addr = inet_addr(args.ladr);

	int opts = 1;
	setsockopt(args.locl, SOL_SOCKET, SO_REUSEADDR, &opts, sizeof(int));
	if (bind(args.locl, (struct sockaddr *)&ladr, sizeof(struct sockaddr_in)) < 0)
	{
		return 1;
	}
	if (strcmp(args.prot, "tcp") == 0)
	{
		listen(args.locl, 96);
	}

	char *pntr = args.bind;
	for (int x = 0; pntr && *pntr && (x < BLEN); ++x)
	{
		char *pnts = strchr(pntr, ',');
		if (pnts) { *pnts = 0; ++pnts; }
		args.bnds[x].sin_family = AF_INET;
		args.bnds[x].sin_port = htons(0);
		args.bnds[x].sin_addr.s_addr = inet_addr(pntr);
		args.blen = (x + 1);
		pntr = NULL;
		if (pnts && *pnts) { pntr = pnts; }
	}

	char *penv = getenv("TIMO");
	bzero(TOBJ, SIZE);
	if (penv)
	{
		args.envr = strdup(penv);
		tims(args.timo, args.envr);
	}
	if (strcmp(TOBJ, "") != 0)
	{
		printf("%s INFO main [%s]\n", date(), TOBJ); fflush(stdout);
	}

	loop(&args);

	return 0;
}
