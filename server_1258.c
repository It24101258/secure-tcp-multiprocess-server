#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <ctype.h>

#define PORT    50258
#define SID     "2410"
#define MAXBUF  4096
#define USERS   "/srv/ie2102/IT24101258/users.txt"
#define LOGFILE "server_IT24101258.log"

/* ── log ── */
void write_log(char *ip, char *user, char *cmd, char *result) {
    FILE *f = fopen(LOGFILE, "a");
    if (!f) return;
    time_t t = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(f, "[%s] IP:%s PID:%d user=%s cmd=%s res=%s\n",
            ts, ip, getpid(), user, cmd, result);
    fclose(f);
}

/* ── response ── */
void send_resp(int sock, char *type, int code, char *msg) {
    char out[512];
    snprintf(out, sizeof(out), "%s %d SID:%s %s\n", type, code, SID, msg);
    send(sock, out, strlen(out), 0);
}

/* ── username validation ── */
int valid_user(char *u) {
    int len = strlen(u);
    if (len < 3 || len > 20) return 0;
    for (int i = 0; i < len; i++)
        if (!isalnum(u[i]) && u[i] != '_') return 0;
    return 1;
}

/* ── register ── */
void do_register(int sock, char *ip, char *user, char *pass) {
    /* check duplicate */
    FILE *f = fopen(USERS, "r");
    if (f) {
        char line[128], u[64], p[64];
        while (fgets(line, sizeof(line), f)) {
            sscanf(line, "%63[^:]:%63s", u, p);
            if (strcmp(u, user) == 0) {
                fclose(f);
                send_resp(sock, "ERR", 409, "user already exists");
                write_log(ip, user, "REGISTER", "ERR 409");
                return;
            }
        }
        fclose(f);
    }
    f = fopen(USERS, "a");
    if (!f) { send_resp(sock, "ERR", 500, "server error"); return; }
    fprintf(f, "%s:%s\n", user, pass);
    fclose(f);
    send_resp(sock, "OK", 200, "registered");
    write_log(ip, user, "REGISTER", "OK 200");
}

/* ── login ── */
int do_login(int sock, char *ip, char *user, char *pass) {
    FILE *f = fopen(USERS, "r");
    if (!f) { send_resp(sock, "ERR", 500, "no users"); return 0; }
    char line[128], u[64], p[64];
    while (fgets(line, sizeof(line), f)) {
        sscanf(line, "%63[^:]:%63s", u, p);
        if (strcmp(u, user) == 0 && strcmp(p, pass) == 0) {
            fclose(f);
            send_resp(sock, "OK", 200, "login ok");
            write_log(ip, user, "LOGIN", "OK 200");
            return 1;
        }
    }
    fclose(f);
    send_resp(sock, "ERR", 401, "invalid credentials");
    write_log(ip, user, "LOGIN", "ERR 401");
    return 0;
}

/* ── handle one client ── */
void handle_client(int sock, char *ip) {
    printf("Child PID:%d  Parent PID:%d  Client:%s\n",
           getpid(), getppid(), ip);

    char username[64] = "anonymous";
    int  logged       = 0;
    int  fail_count   = 0;

    while (1) {
        /* A1 — receive frame */
        char buf[MAXBUF + 64];
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = 0;

        /* parse LEN header */
        int payload_len = 0;
        if (sscanf(buf, "LEN:%d", &payload_len) != 1) {
            send_resp(sock, "ERR", 400, "bad header");
            write_log(ip, username, "?", "ERR 400");
            break;
        }
        if (payload_len > MAXBUF) {
            send_resp(sock, "ERR", 413, "payload too large");
            write_log(ip, username, "?", "ERR 413");
            break;
        }

        /* find payload after \n */
        char *payload = strchr(buf, '\n');
        if (!payload) break;
        payload++;

        /* A4 — parse and validate command */
        char cmd[32] = {0}, arg1[64] = {0}, arg2[64] = {0};
        sscanf(payload, "%31s %63s %63s", cmd, arg1, arg2);

        /* A4 — brute force lockout */
        if (fail_count >= 3) {
            send_resp(sock, "ERR", 429, "locked out");
            write_log(ip, username, cmd, "ERR 429");
            break;
        }

        /* A3 — command dispatch */
        if (strcmp(cmd, "REGISTER") == 0) {
            if (!valid_user(arg1)) {
                send_resp(sock, "ERR", 400, "bad username");
                write_log(ip, username, "REGISTER", "ERR 400");
            } else {
                do_register(sock, ip, arg1, arg2);
            }

        } else if (strcmp(cmd, "LOGIN") == 0) {
            if (!valid_user(arg1)) {
                send_resp(sock, "ERR", 400, "bad username");
            } else {
                logged = do_login(sock, ip, arg1, arg2);
                if (logged) {
                    strncpy(username, arg1, sizeof(username) - 1);
                    fail_count = 0;
                } else {
                    fail_count++;
                }
            }

        } else if (strcmp(cmd, "LOGOUT") == 0) {
            send_resp(sock, "OK", 200, "bye");
            write_log(ip, username, "LOGOUT", "OK 200");
            break;

        } else {
            send_resp(sock, "ERR", 404, "unknown command");
            write_log(ip, username, cmd, "ERR 404");
        }
    }

    close(sock);
}

/* ── main ── */
int main() {
    /* create data directory */
    system("mkdir -p /srv/ie2102/IT24101258");

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    bind(srv, (struct sockaddr *)&addr, sizeof(addr));
    listen(srv, 10);

    signal(SIGCHLD, SIG_IGN);   /* A2 — no zombie processes */

    printf("Server PID:%d  Port:%d  SID:%s\n", getpid(), PORT, SID);

    while (1) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int c = accept(srv, (struct sockaddr *)&cli, &clen);
        char *ip = inet_ntoa(cli.sin_addr);

        if (fork() == 0) {      /* A2 — child handles client */
            close(srv);
            handle_client(c, ip);
            exit(0);
        }
        close(c);               /* parent keeps accepting */
    }
    return 0;
}
