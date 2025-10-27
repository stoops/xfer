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

#define BLEN 10
#define DLEN 15
#define DSIZ 90
#define NUMB 3000
#define SIZE 9000
#define TLEN 75000

int didx = 0;
char dobj[DLEN][DSIZ];
char tobj[SIZE];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct argp
{
	int locl, lprt, blen;
	char *prot, *ladr, *bind, *file, *envr;
	struct sockaddr_in bnds[BLEN];
	int timo[TLEN];
};

struct conp
{
	int stat, dprt, stop;
	int conn, remo, comm;
	char srcs[SIZE], port[SIZE], dsts[SIZE];
	char *flag;
	time_t last, logs[2];
	struct sockaddr_in addr, dest;
	pthread_t thrd;
	struct argp *argv;
};

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

int safe(char *strs)
{
	if (!strs) { return 0; }
	int port = atoi(strs);
	if ((port < 0x0000) || (0xffff < port)) { return 0; }
	return port;
}

char *date()
{
	time_t secs = time(NULL);
	struct tm *info = localtime(&secs);
	int modi = ((secs % (DLEN - 1)) + 1);
	pthread_mutex_lock(&lock);
	if (modi != didx)
	{
		bzero(dobj[modi], DSIZ);
		strftime(dobj[modi], 50, "%Y-%m-%d_%H:%M:%S", info);
		didx = modi;
	}
	pthread_mutex_unlock(&lock);
	return dobj[didx];
}

int gtim(int *list, int port)
{
	int timo = list[0];
	if ((port < 0x0000) || (0xffff < port))
	{
		port = 0;
	}
	if (list[port] != 0)
	{
		timo = list[port];
	}
	return timo;
}

void catn(int a, int b)
{
	char buff[96];
	bzero(buff, 96);
	snprintf(buff, 64, "%d=%d, ", a, b);
	int i = 0;
	int l = strlen(tobj);
	int n = strlen(buff);
	while ((i < n) && (l < (SIZE - 11)))
	{
		tobj[l] = buff[i]; ++i; ++l;
	}
}

void prts(int *outp, char *envr, char *valu)
{
	while (1)
	{
		char *pntr = strchr(envr, ',');
		if (pntr) { *pntr = 0; ++pntr; }
		outp[safe(envr)] = safe(valu);
		catn(safe(envr), safe(valu));
		if (!pntr || !(*pntr)) { break; }
		envr = pntr;
	}
}

void pars(int *outp, char *envr)
{
	while (1)
	{
		char *pntr = strchr(envr, ':');
		if (pntr) { *pntr = 0; ++pntr; }
		if (!pntr || !(*pntr)) { break; }
		prts(outp, envr, pntr);
		envr = pntr;
	}
}

void timo(int *outp, char *envr)
{
	while (1)
	{
		char *pntr = strchr(envr, ';');
		if (pntr) { *pntr = 0; ++pntr; }
		pars(outp, envr);
		if (!pntr || !(*pntr)) { break; }
		envr = pntr;
	}
}

void uadr(char **pntr, int *port, char *inpt)
{
	char *temp = strchr(inpt, ':');
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
	if (leng < 1) { return -1; }
	while (leng > 0)
	{
		int wlen = send(sock, buff, leng, 0);
		if (wlen < 0) { return -1; }
		buff += wlen; leng -= wlen;
	}
	if (leng > 0) { return -2; }
	return 1;
}

int pall(int sock, unsigned char *buff, int leng)
{
	int dlen = 0;
	unsigned char temp[2];
	int rlen = read(sock, temp, 2);
	if (rlen < 2) { return -1; }
	rlen = ((temp[0] << 8) | temp[1]);
	if ((rlen < 1) || (leng < rlen)) { return -2; }
	leng = rlen;
	while (leng > 0)
	{
		rlen = read(sock, buff, leng);
		if (rlen < 0) { return -3; }
		buff += rlen; leng -= rlen;
		dlen += rlen;
	}
	if (leng > 0) { return 0; }
	return dlen;
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

void *xfer(void *argv)
{
	struct conp *cons = (struct conp *)argv;
	struct argp *args = cons->argv;

	cons->flag = "*";
	bzero(cons->srcs, SIZE);
	inet_ntop(AF_INET, &(cons->addr.sin_addr), cons->srcs, INET_ADDRSTRLEN);
	bzero(cons->port, SIZE);
	snprintf(cons->port, SIZE - 11, "%d", ntohs(cons->addr.sin_port));
	bzero(cons->dsts, SIZE);
	comd(args->file, cons->srcs, cons->port, args->prot, cons->dsts, SIZE - 11);

	printf("%s INFO conn [%s:%s] ! [%s] [%s]\n", date(), cons->srcs, cons->port, cons->dsts, args->prot); fflush(stdout);

	if (strcmp(cons->dsts, "") == 0)
	{
		cons->flag = "dest"; cons->stop |= 1;
	}

	bzero(&cons->dest, sizeof(struct sockaddr_in));
	char *dsts = cons->dsts;
	int *port = &cons->dprt;
	uadr(&dsts, port, cons->dsts);
	cons->dest.sin_family = AF_INET;
	cons->dest.sin_port = htons(*port);
	cons->dest.sin_addr.s_addr = inet_addr(dsts);

	int bidx = (rand() % args->blen);
	if (strcmp(args->prot, "udp") == 0)
	{
		cons->remo = socket(AF_INET, SOCK_DGRAM, 0);
		if (bind(cons->remo, (struct sockaddr *)&args->bnds[bidx], sizeof(struct sockaddr_in)) < 0)
		{
			cons->flag = "bind"; cons->stop |= 2;
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

	int sels, dlen, slen;
	int kind = (strcmp(args->prot, "udp") == 0) ? 1 : 2;
	int maxf = (cons->conn > cons->remo) ? cons->conn : cons->remo;
	unsigned int clen;
	unsigned char buff[SIZE];
	fd_set rfds;
	struct timeval tout;
	struct sockaddr_in cadr;

	cons->stat = 1;

	while (1)
	{
		if ((cons->stat != 1) || (cons->stop != 0)) { break; }

		FD_ZERO(&rfds);
		FD_SET(cons->conn, &rfds);
		FD_SET(cons->remo, &rfds);
		tout.tv_sec = 3;
		tout.tv_usec = 0;
		sels = select(maxf + 1, &rfds, NULL, NULL, &tout);
		if (sels < 0) { cons->flag = "sels"; break; }

		if ((cons->stat != 1) || (cons->stop != 0)) { break; }

		time_t secs = time(NULL);

		if (FD_ISSET(cons->conn, &rfds))
		{
			if (kind == 1)
			{
				dlen = pall(cons->conn, buff, SIZE);
				if (dlen < 1) { cons->flag = "read-conn"; break; }
				struct sockaddr_in *cptr = &cons->dest;
				slen = sendto(cons->remo, buff, dlen, 0, (struct sockaddr *)cptr, sizeof(struct sockaddr_in));
				if (slen < 1) { cons->flag = "send-conn"; break; }
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
				clen = sizeof(struct sockaddr_in);
				bzero(&cadr, clen);
				dlen = recvfrom(cons->remo, buff, SIZE, 0, (struct sockaddr *)&cadr, &clen);
				if (dlen < 1) { cons->flag = "read-remo"; break; }
				struct sockaddr_in *cptr = &cons->addr;
				slen = sendto(args->locl, buff, dlen, 0, (struct sockaddr *)cptr, sizeof(struct sockaddr_in));
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

	cons->stat = -1;

	return NULL;
}

void *mgmt(void *argv)
{
	struct conp *cons = (struct conp *)argv;
	struct argp *args = cons->argv;

	int timo = 0, news = 30, tcpx = 3000;
	int kind = (strcmp(args->prot, "udp") == 0) ? 1 : 2;

	while (1)
	{
		int alen = 0, blen = 0;
		time_t secs = time(NULL);

		for (int x = 0; x < NUMB; ++x)
		{
			if (cons[x].stat == 0) { continue; }
			if (cons[x].stat == 2)
			{
				if ((kind != 0) && ((secs - cons[x].last) >= news))
				{
					cons[x].flag = "news"; cons[x].stop |= 16;
				}
			}
			if (cons[x].stat > 0)
			{
				timo = gtim(args->timo, cons[x].dprt);
				if ((kind == 1) && ((secs - cons[x].last) >= timo))
				{
					cons[x].flag = "time"; cons[x].stop |= 32;
				}
				if ((kind == 2) && ((secs - cons[x].last) >= tcpx))
				{
					cons[x].flag = "tcpx"; cons[x].stop |= 64;
				}
			}
			if ((cons[x].stat < 0) || (cons[x].stop > 0))
			{
				timo = gtim(args->timo, cons[x].dprt);
				printf("%s INFO fins [%s:%s] * [%s:%d] [%s:%d] [%s][%d:%d]\n", date(), cons[x].srcs, cons[x].port, cons[x].dsts, cons[x].dprt, args->prot, timo, cons[x].flag, cons[x].stat, cons[x].stop); fflush(stdout);
				fins(&cons[x].comm);
				fins(&cons[x].remo);
				fins(&cons[x].conn);
				if (cons[x].stat == -1)
				{
					printf("%s INFO join [%s:%s] * [%s:%d] [%s:%d] [%s][%d:%d]\n", date(), cons[x].srcs, cons[x].port, cons[x].dsts, cons[x].dprt, args->prot, timo, cons[x].flag, cons[x].stat, cons[x].stop); fflush(stdout);
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

		printf("%s INFO mgmt [%d:%d]\n", date(), alen, blen); fflush(stdout);

		sleep(3);
	}

	return NULL;
}

int main(int argc, char **argv)
{
	unsigned int clen;
	unsigned char buff[SIZE], temp[2];
	struct sockaddr_in ladr, cadr;
	pthread_t thrd;

	struct argp args;
	struct conp *cons = malloc(NUMB * sizeof(struct conp));

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

	for (int x = 0; x < NUMB; ++x)
	{
		bzero(&(cons[x]), sizeof(struct conp));
		cons[x].argv = &args;
	}

	if (strcmp(args.prot, "udp") == 0)
	{
		args.locl = socket(AF_INET, SOCK_DGRAM, 0);
	}
	else
	{
		args.locl = socket(AF_INET, SOCK_STREAM, 0);
	}

	srand(time(NULL));
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
	args.timo[0] = 130;
	bzero(tobj, SIZE);
	if (penv)
	{
		args.envr = strdup(penv);
		timo(args.timo, args.envr);
	}
	if (strcmp(tobj, "") != 0)
	{
		printf("%s INFO main [%s]\n", date(), tobj); fflush(stdout);
	}

	pthread_create(&thrd, NULL, mgmt, (void *)&cons[0]);

	int dlen, plen, wlen;
	while (1)
	{
		int indx = -1;
		clen = sizeof(struct sockaddr_in);
		bzero(&cadr, clen);

		if (strcmp(args.prot, "udp") == 0)
		{
			dlen = recvfrom(args.locl, buff, SIZE, 0, (struct sockaddr *)&cadr, &clen);
			if (dlen < 1) { break; }
			clen = sizeof(struct sockaddr_in);
			for (int x = 0; x < NUMB; ++x)
			{
				if ((cons[x].stat >= 1) && (memcmp(&cons[x].addr, &cadr, clen) == 0))
				{
					indx = (1 * (x + 11));
				}
				if ((cons[x].stat == 0) && (indx == -1))
				{
					indx = (-1 * (x + 11));
				}
			}
			if (indx < -1)
			{
				int pipo[2];
				plen = socketpair(AF_UNIX, SOCK_DGRAM, 0, pipo);
				if (plen < 0) { break; }
				indx = ((indx * -1) - 11);
				bcopy(&cadr, &cons[indx].addr, clen);
				cons[indx].comm = pipo[1];
				cons[indx].conn = pipo[0];
				cons[indx].last = time(NULL);
				cons[indx].argv = &args;
				cons[indx].stat = 2;
				pthread_create(&cons[indx].thrd, NULL, xfer, (void *)&cons[indx]);
				indx = (1 * (indx + 11));
			}
			if (indx > -1)
			{
				indx = ((indx * 1) - 11);
				int sock = cons[indx].comm;
				temp[0] = ((dlen >> 8) & 0xff); temp[1] = (dlen & 0xff);
				wlen = write(sock, temp, 2);
				if (wlen < 0) { printf("%s WARN wlen [%s]\n", date(), args.prot); fflush(stdout); }
				wlen = write(sock, buff, dlen);
				if (wlen < 0) { printf("%s WARN dlen [%s]\n", date(), args.prot); fflush(stdout); }
			}
			if (indx == -1)
			{
				printf("%s WARN nofd [%s]\n", date(), args.prot); fflush(stdout);
			}
		}

		else
		{
			int conn = accept(args.locl, (struct sockaddr *)&cadr, &clen);
			if (conn < 1) { break; }
			clen = sizeof(struct sockaddr_in);
			for (int x = 0; x < NUMB; ++x)
			{
				if ((cons[x].stat == 0) && (indx == -1))
				{
					indx = x;
				}
			}
			if (indx > -1)
			{
				bcopy(&cadr, &cons[indx].addr, clen);
				cons[indx].conn = conn;
				cons[indx].last = time(NULL);
				cons[indx].argv = &args;
				cons[indx].stat = 2;
				pthread_create(&cons[indx].thrd, NULL, xfer, (void *)&cons[indx]);
			}
			if (indx == -1)
			{
				printf("%s WARN nofd [%s]\n", date(), args.prot); fflush(stdout);
				fins(&conn);
			}
		}
	}

	return 0;
}
