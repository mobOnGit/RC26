/*
 NetBoX - User Application
 Phase I : UDP client operations for login, logout and unregister.
 Phase II: publish, remove, list (UDP) and versions (TCP client of the DS).
 */
//TODO: Handle CTRL + C exit
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE //FIX FOR MSG_DONTWAIT MACOS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>
#include <time.h>

/*  Default values, used when -n / -p are not given.*/
#define DEFAULT_DS_IP   "193.136.138.142"
#define DEFAULT_DS_PORT "59000"

#define UDP_TIMEOUT_MS  5000
#define TCP_TIMEOUT_S   5
#define MAX_LINE        512
#define MAX_MSG         512
#define MAX_UDP_REPLY   4096          /* RLS: up to 50 filenames of 24 chars  */
#define MAX_TCP_REPLY   (1 << 20)     /* upper bound for an RVR reply         */

#define MAX_FILENAME    24
#define MAX_LABEL       20
#define MAX_FSIZE       10000000L
#define MAX_RLS_FILES   50

#define UDP_MAX_ATTEMPTS 3


/* Global application state                                          */

typedef struct {
    char peerport[8];      /* our own TCP port for file transfers, as text  */
    char ds_ip[64];
    char ds_port[8];
    struct sockaddr_in ds_addr;   /* DS address, resolved once at start-up  */

    int  logged_in;        /* 0 = no user logged in, 1 = logged in         */
    char uid[7];           /* 6 digits + '\0'                              */
    char password[9];      /* 8 alphanumeric chars + '\0'                  */

    int  udp_fd;
} app_state_t;



/* Validation helpers                                                 */

/* UID must be exactly 6 decimal digits */
static int valid_uid(const char *uid) {
    if (strlen(uid) != 6) return 0;
    for (int i = 0; i < 6; i++)
        if (!isdigit((unsigned char) uid[i])) return 0;
    return 1;
}

/* password must be exactly 8 alphanumeric ASCII characters */
static int valid_password(const char *pw) {
    if (strlen(pw) != 8) return 0;
    for (int i = 0; i < 8; i++)
        if (!isalnum((unsigned char) pw[i])) return 0;
    return 1;
}

/* port must be a decimal integer in [1, 65535] */
static int valid_port(const char *port) {
    size_t len = strlen(port);
    if (len == 0 || len > 5) return 0;
    for (size_t i = 0; i < len; i++)
        if (!isdigit((unsigned char) port[i])) return 0;
    long p = strtol(port, NULL, 10);
    return (p >= 1 && p <= 65535);
}

/* Filename: at most 24 chars; base name of letters, digits, '-' and '_',
   followed by '.' and an extension of exactly 3 alphanumeric chars. */
static int valid_filename(const char *fn) {
    size_t len = strlen(fn);
    if (len < 5 || len > MAX_FILENAME) return 0;   /* >=1 char + ".xxx" */
    if (fn[len - 4] != '.') return 0;
    for (size_t i = 0; i < len - 4; i++) {
        unsigned char c = (unsigned char) fn[i];
        if (!isalnum(c) && c != '-' && c != '_') return 0;
    }
    for (size_t i = len - 3; i < len; i++)
        if (!isalnum((unsigned char) fn[i])) return 0;
    return 1;
}

/* Label: 1 to 20 chars of letters, digits, '-' and '_' */
static int valid_label(const char *label) {
    size_t len = strlen(label);
    if (len < 1 || len > MAX_LABEL) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char) label[i];
        if (!isalnum(c) && c != '-' && c != '_') return 0;
    }
    return 1;
}

/* Fsize as received in a protocol message: 1 to 8 digits, <= 10,000,000 */
static int valid_fsize_str(const char *s) {
    size_t len = strlen(s);
    if (len < 1 || len > 8) return 0;
    for (size_t i = 0; i < len; i++)
        if (!isdigit((unsigned char) s[i])) return 0;
    return strtol(s, NULL, 10) <= MAX_FSIZE;
}

/* Copy a port string to dst in normalised form (no leading zeros) */
static void normalise_port(char *dst, size_t dst_size, const char *port) {
    snprintf(dst, dst_size, "%ld", strtol(port, NULL, 10));
}


/* Resolve the DS address once (IPv4). The same address and port are
   used for the UDP and the TCP servers of the DS. */
static int resolve_ds(app_state_t *st) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int err = getaddrinfo(st->ds_ip, st->ds_port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "Erro a resolver o endereco do DS (%s): %s\n",
                st->ds_ip, gai_strerror(err));
        return -1;
    }
    if (res == NULL || res->ai_addrlen != sizeof(st->ds_addr)) {
        fprintf(stderr, "Endereco do DS invalido.\n");
        freeaddrinfo(res);
        return -1;
    }
    memcpy(&st->ds_addr, res->ai_addr, sizeof(st->ds_addr));
    freeaddrinfo(res);
    return 0;
}


/* UDP communication with the Directory Server                        */

/* Milliseconds elapsed since 'start' */
static long elapsed_ms(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long) (now.tv_sec - start->tv_sec) * 1000L
         + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

/*
 Sends 'request' (a '\n' is appended) to the DS and waits for the reply.
 Returns 0 on success (reply stored without trailing \n / \r), -1 on error.
 */
static int udp_exchange(app_state_t *st, const char *request,
                        char *reply, size_t reply_size) {
    char msg[MAX_MSG];
    int len = snprintf(msg, sizeof(msg), "%s\n", request);
    if (len < 0 || (size_t) len >= sizeof(msg)) {
        fprintf(stderr, "Pedido demasiado grande.\n");
        return -1;
    }

    /* Discard stale datagrams (e.g. a late reply to a previous timeout) */
    char tmp[MAX_UDP_REPLY];
    while (recvfrom(st->udp_fd, tmp, sizeof(tmp), MSG_DONTWAIT, NULL, NULL) > 0) //FIXME : try multiple times , remove MSG_DONTWAIT
        ;

    ssize_t n = sendto(st->udp_fd, msg, (size_t) len, 0,
                       (struct sockaddr *) &st->ds_addr, sizeof(st->ds_addr));
    if (n == -1) {
        perror("sendto");
        return -1;
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    ssize_t r;
    for (;;) {
        long remaining = UDP_TIMEOUT_MS - elapsed_ms(&start); //SET SOCKET OPTIONS - TIME ||| TRY 3 TIMES BEFORE RETURNING ERROR
        if (remaining <= 0) {
            fprintf(stderr, "Sem resposta do DS (timeout).\n");
            return -1;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(st->udp_fd, &rfds);
        struct timeval tv;
        tv.tv_sec  = remaining / 1000;
        tv.tv_usec = (remaining % 1000) * 1000;

        int ready = select(st->udp_fd + 1, &rfds, NULL, NULL, &tv);
        if (ready == -1) {
            if (errno == EINTR) continue;
            perror("select");
            return -1;
        } else if (ready == 0) {
            fprintf(stderr, "Sem resposta do DS (timeout).\n");
            return -1;
        }

        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        r = recvfrom(st->udp_fd, reply, reply_size - 1, 0,
                     (struct sockaddr *) &from, &fromlen);
        if (r == -1) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            return -1;
        }

        /* Ignore datagrams that do not come from the DS */
        if (from.sin_addr.s_addr != st->ds_addr.sin_addr.s_addr ||
            from.sin_port != st->ds_addr.sin_port)
            continue;
        break;
    }

    reply[r] = '\0';
    /* strip trailing \n and/or \r if present */
    while (r > 0 && (reply[r - 1] == '\n' || reply[r - 1] == '\r')) {
        reply[--r] = '\0';
    }
    return 0;
}

/*
 Parses a reply of the form "<expected> <status>" (exactly two tokens).
 Returns  0 -> status stored in 'status'
          1 -> the DS answered a bare "ERR" (or "<expected> ERR" is
               returned as status "ERR" with 0)
         -1 -> malformed / unexpected reply
 */
static int parse_reply(const char *reply, const char *expected,
                       char *status, size_t status_size) {
    if (strcmp(reply, "ERR") == 0) return 1;

    char cmd[8], s[8], extra[2];
    if (sscanf(reply, "%7s %7s %1s", cmd, s, extra) != 2) return -1;
    if (strcmp(cmd, expected) != 0) return -1;

    snprintf(status, status_size, "%s", s);
    return 0;
}

/* Common handling of the two non-status outcomes of parse_reply().
   Returns 1 if the caller should stop processing the reply. */
static int reply_failed(int rc, const char *reply) {
    if (rc == 1) {
        printf("O DS respondeu ERR (pedido invalido).\n");
        return 1;
    }
    if (rc == -1) {
        printf("Resposta inesperada do DS: '%s'. Interacao terminada.\n", reply);
        return 1;
    }
    return 0;
}


/* TCP communication with the Directory Server                        */

/* Write all 'len' bytes, coping with partial writes. 0 = ok, -1 = error */
static int write_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        buf += n;
        len -= (size_t) n;
    }
    return 0;
}

/* Open a TCP connection to the DS, with send/receive timeouts.
   Returns the socket, or -1 on error (already reported). */
static int tcp_connect_ds(app_state_t *st) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec  = TCP_TIMEOUT_S;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *) &st->ds_addr, sizeof(st->ds_addr)) == -1) {
        fprintf(stderr, "Erro a ligar ao DS por TCP: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/*
 Reads one reply line from a TCP socket: everything up to the first '\n'
 (or until the peer closes the connection). Copes with partial reads.
 Returns a malloc'd string without the trailing '\n' / '\r', or NULL on
 error (already reported). The caller must free() the result.
 */
static char *tcp_read_line(int fd, size_t max_len) {
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (buf == NULL) {
        fprintf(stderr, "Sem memoria.\n");
        return NULL;
    }

    for (;;) {
        if (len + 1 >= cap) {
            if (cap >= max_len) {
                fprintf(stderr, "Resposta do DS demasiado longa.\n");
                free(buf);
                return NULL;
            }
            size_t ncap = cap * 2;
            if (ncap > max_len) ncap = max_len;
            char *nb = realloc(buf, ncap);
            if (nb == NULL) {
                fprintf(stderr, "Sem memoria.\n");
                free(buf);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }

        ssize_t n = read(fd, buf + len, cap - len - 1);
        if (n == -1) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                fprintf(stderr, "Sem resposta do DS (timeout).\n");
            else
                perror("read");
            free(buf);
            return NULL;
        }
        if (n == 0) break;   /* connection closed by the DS */

        char *nl = memchr(buf + len, '\n', (size_t) n);
        len += (size_t) n;
        if (nl != NULL) {
            len = (size_t) (nl - buf);
            break;
        }
    }

    buf[len] = '\0';
    if (len > 0 && buf[len - 1] == '\r') buf[--len] = '\0';
    return buf;
}


/* Session helpers                                                    */

static void set_session(app_state_t *st, const char *uid, const char *pw) {
    st->logged_in = 1;
    snprintf(st->uid, sizeof(st->uid), "%s", uid);
    snprintf(st->password, sizeof(st->password), "%s", pw);
}

static void clear_session(app_state_t *st) {
    st->logged_in = 0;
    st->uid[0] = '\0';
    st->password[0] = '\0';
}


/* Phase I commands                                                   */

static void cmd_login(app_state_t *st, const char *uid, const char *pw) {
    if (!valid_uid(uid)) {
        printf("UID invalido: deve ter exatamente 6 digitos.\n");
        return;
    }
    if (!valid_password(pw)) {
        printf("Password invalida: deve ter exatamente 8 caracteres alfanumericos.\n");
        return;
    }

    char req[MAX_MSG];
    snprintf(req, sizeof(req), "LIN %s %s %s", uid, pw, st->peerport);

    char reply[MAX_MSG];
    if (udp_exchange(st, req, reply, sizeof(reply)) != 0) return;

    char status[8];
    if (reply_failed(parse_reply(reply, "RLI", status, sizeof(status)), reply))
        return;

    if (strcmp(status, "OK") == 0) {
        printf("Login efetuado com sucesso.\n");
        set_session(st, uid, pw);
    } else if (strcmp(status, "REG") == 0) {
        printf("Novo utilizador registado e login efetuado com sucesso.\n");
        set_session(st, uid, pw);
    } else if (strcmp(status, "NOK") == 0) {
        printf("Tentativa de login incorreta (password incorreta).\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("O DS respondeu ERR (pedido invalido).\n");
    } else {
        printf("Resposta inesperada do DS: '%s'.\n", reply);
    }
}

static void cmd_logout(app_state_t *st) {
    if (!st->logged_in) {
        printf("Nenhum utilizador com sessao iniciada.\n");
        return;
    }

    char req[MAX_MSG];
    snprintf(req, sizeof(req), "LOU %s %s", st->uid, st->password);

    char reply[MAX_MSG];
    if (udp_exchange(st, req, reply, sizeof(reply)) != 0) return;

    char status[8];
    if (reply_failed(parse_reply(reply, "RLO", status, sizeof(status)), reply))
        return;

    if (strcmp(status, "OK") == 0) {
        printf("Logout efetuado com sucesso.\n");
        clear_session(st);
    } else if (strcmp(status, "NLG") == 0) {
        printf("O utilizador nao tinha sessao iniciada no DS.\n");
        clear_session(st);
    } else if (strcmp(status, "UNR") == 0) {
        printf("Utilizador nao registado no DS.\n");
        clear_session(st);
    } else if (strcmp(status, "WRP") == 0) {
        printf("Password incorreta.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("O DS respondeu ERR (pedido invalido).\n");
    } else {
        printf("Resposta inesperada do DS: '%s'.\n", reply);
    }
}

static void cmd_unregister(app_state_t *st) {
    if (!st->logged_in) {
        printf("Nenhum utilizador com sessao iniciada.\n");
        return;
    }

    char req[MAX_MSG];
    snprintf(req, sizeof(req), "UNR %s %s", st->uid, st->password);

    char reply[MAX_MSG];
    if (udp_exchange(st, req, reply, sizeof(reply)) != 0) return;

    char status[8];
    if (reply_failed(parse_reply(reply, "RUR", status, sizeof(status)), reply))
        return;

    if (strcmp(status, "OK") == 0) {
        printf("Unregister efetuado com sucesso.\n");
        clear_session(st); /* unregister implies logout */
    } else if (strcmp(status, "NOK") == 0) {
        printf("O utilizador nao tinha sessao iniciada no DS.\n");
        clear_session(st);
    } else if (strcmp(status, "UNR") == 0) {
        printf("Utilizador nao registado no DS.\n");
        clear_session(st);
    } else if (strcmp(status, "WRP") == 0) {
        printf("Password incorreta.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("O DS respondeu ERR (pedido invalido).\n");
    } else {
        printf("Resposta inesperada do DS: '%s'.\n", reply);
    }
}

static void cmd_exit(app_state_t *st, int *keep_running) {
    if (st->logged_in) {
        printf("Deve efetuar logout antes de sair (comando 'logout').\n");
        return;
    }
    *keep_running = 0;
}


/* Phase II commands                                                  */

/* publish filename label  ->  PUB UID password filename Fsize label */
static void cmd_publish(app_state_t *st, const char *fn, const char *label) {
    if (!st->logged_in) {
        printf("Nenhum utilizador com sessao iniciada. Faca login primeiro.\n");
        return;
    }
    if (!valid_filename(fn)) {
        printf("Nome de ficheiro invalido: max. 24 caracteres (letras, digitos, '-', '_'),"
               " seguido de '.' e extensao de 3 caracteres alfanumericos.\n");
        return;
    }
    if (!valid_label(label)) {
        printf("Label invalida: 1 a 20 caracteres (letras, digitos, '-', '_').\n");
        return;
    }

    /* The file must exist in the local directory before contacting the DS */
    struct stat sb;
    if (stat(fn, &sb) == -1) {
        if (errno == ENOENT)
            printf("O ficheiro '%s' nao existe na diretoria local.\n", fn);
        else
            printf("Erro ao aceder ao ficheiro '%s': %s\n", fn, strerror(errno));
        return;
    }
    if (!S_ISREG(sb.st_mode)) {
        printf("'%s' nao e um ficheiro regular.\n", fn);
        return;
    }
    if (access(fn, R_OK) != 0) {
        printf("O ficheiro '%s' nao tem permissao de leitura.\n", fn);
        return;
    }
    if (sb.st_size > MAX_FSIZE) {
        printf("O ficheiro '%s' excede o tamanho maximo (%ld bytes).\n",
               fn, MAX_FSIZE);
        return;
    }
    long fsize = (long) sb.st_size;

    char req[MAX_MSG];
    snprintf(req, sizeof(req), "PUB %s %s %s %ld %s",
             st->uid, st->password, fn, fsize, label);

    char reply[MAX_MSG];
    if (udp_exchange(st, req, reply, sizeof(reply)) != 0) return;

    char status[8];
    if (reply_failed(parse_reply(reply, "RPB", status, sizeof(status)), reply))
        return;

    if (strcmp(status, "OK") == 0) {
        printf("Ficheiro '%s' publicado com sucesso (%ld bytes, label '%s').\n",
               fn, fsize, label);
    } else if (strcmp(status, "NOK") == 0) {
        printf("Publicacao sem sucesso.\n");
    } else if (strcmp(status, "NLG") == 0) {
        printf("O utilizador nao tem sessao iniciada no DS. Faca login novamente.\n");
        clear_session(st);
    } else if (strcmp(status, "UNR") == 0) {
        printf("Utilizador nao registado no DS.\n");
        clear_session(st);
    } else if (strcmp(status, "WRP") == 0) {
        printf("Password incorreta.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("O DS respondeu ERR (pedido invalido).\n");
    } else {
        printf("Resposta inesperada do DS: '%s'.\n", reply);
    }
}

/* remove filename  ->  REM UID password filename */
static void cmd_remove(app_state_t *st, const char *fn) {
    if (!st->logged_in) {
        printf("Nenhum utilizador com sessao iniciada. Faca login primeiro.\n");
        return;
    }
    if (!valid_filename(fn)) {
        printf("Nome de ficheiro invalido: max. 24 caracteres (letras, digitos, '-', '_'),"
               " seguido de '.' e extensao de 3 caracteres alfanumericos.\n");
        return;
    }

    char req[MAX_MSG];
    snprintf(req, sizeof(req), "REM %s %s %s", st->uid, st->password, fn);

    char reply[MAX_MSG];
    if (udp_exchange(st, req, reply, sizeof(reply)) != 0) return;

    char status[8];
    if (reply_failed(parse_reply(reply, "RRM", status, sizeof(status)), reply))
        return;

    if (strcmp(status, "OK") == 0) {
        printf("Ficheiro '%s' removido com sucesso.\n", fn);
    } else if (strcmp(status, "NOK") == 0) {
        printf("Recurso nao encontrado: '%s' nao foi publicado por este utilizador.\n", fn);
    } else if (strcmp(status, "NLG") == 0) {
        printf("O utilizador nao tem sessao iniciada no DS. Faca login novamente.\n");
        clear_session(st);
    } else if (strcmp(status, "UNR") == 0) {
        printf("Utilizador nao registado no DS.\n");
        clear_session(st);
    } else if (strcmp(status, "WRP") == 0) {
        printf("Password incorreta.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("O DS respondeu ERR (pedido invalido).\n");
    } else {
        printf("Resposta inesperada do DS: '%s'.\n", reply);
    }
}

/* list  ->  LST ; reply: RLS status [filename]* */
static void cmd_list(app_state_t *st) {
    char reply[MAX_UDP_REPLY];
    if (udp_exchange(st, "LST", reply, sizeof(reply)) != 0) return;

    if (strcmp(reply, "ERR") == 0) {
        printf("O DS respondeu ERR (pedido invalido).\n");
        return;
    }

    char buf[MAX_UDP_REPLY];
    snprintf(buf, sizeof(buf), "%s", reply);

    char *save = NULL;
    char *cmd    = strtok_r(buf, " ", &save);
    char *status = strtok_r(NULL, " ", &save);
    if (cmd == NULL || status == NULL || strcmp(cmd, "RLS") != 0) {
        printf("Resposta inesperada do DS: '%s'. Interacao terminada.\n", reply);
        return;
    }

    if (strcmp(status, "NOK") == 0 || strcmp(status, "ERR") == 0) {
        if (strtok_r(NULL, " ", &save) != NULL) {
            printf("Resposta inesperada do DS: '%s'. Interacao terminada.\n", reply);
        } else if (strcmp(status, "NOK") == 0) {
            printf("Nao existem recursos publicados.\n");
        } else {
            printf("O DS respondeu ERR (pedido invalido).\n");
        }
        return;
    }

    if (strcmp(status, "OK") != 0) {
        printf("Resposta inesperada do DS: '%s'. Interacao terminada.\n", reply);
        return;
    }

    /* Validate the whole list before showing anything */
    char *files[MAX_RLS_FILES];
    int count = 0;
    char *tok;
    while ((tok = strtok_r(NULL, " ", &save)) != NULL) {
        if (count == MAX_RLS_FILES || !valid_filename(tok)) {
            printf("Resposta inesperada do DS: '%s'. Interacao terminada.\n", reply);
            return;
        }
        files[count++] = tok;
    }

    if (count == 0) {
        printf("Nao existem recursos publicados.\n");
        return;
    }

    printf("Recursos disponiveis (%d):\n", count);
    for (int i = 0; i < count; i++)
        printf("  %2d. %s\n", i + 1, files[i]);
}

/* One entry of an RVR reply */
typedef struct {
    char uid[7];
    long fsize;
    char label[MAX_LABEL + 1];
    char time[48];
    int  available;
} version_t;

/* versions filename  ->  (TCP) VRS filename ;
   reply: RVR status [UID Fsize label publication_time availability]* */
static void cmd_versions(app_state_t *st, const char *fn) {
    if (!valid_filename(fn)) {
        printf("Nome de ficheiro invalido: max. 24 caracteres (letras, digitos, '-', '_'),"
               " seguido de '.' e extensao de 3 caracteres alfanumericos.\n");
        return;
    }

    int fd = tcp_connect_ds(st);
    if (fd == -1) return;

    char req[MAX_MSG];
    int len = snprintf(req, sizeof(req), "VRS %s\n", fn);
    if (write_all(fd, req, (size_t) len) != 0) {
        fprintf(stderr, "Erro a enviar pedido ao DS: %s\n", strerror(errno));
        close(fd);
        return;
    }

    char *reply = tcp_read_line(fd, MAX_TCP_REPLY); //read indefinetly till the end '\n'
    close(fd);
    if (reply == NULL) return;

    if (strcmp(reply, "ERR") == 0) {
        printf("O DS respondeu ERR (pedido invalido).\n");
        free(reply);
        return;
    }

    char *buf = strdup(reply);
    if (buf == NULL) {
        fprintf(stderr, "Sem memoria.\n");
        free(reply);
        return;
    }

    version_t *v = NULL;
    int count = 0, ok = 0;
    char *save = NULL;
    char *cmd    = strtok_r(buf, " ", &save);
    char *status = strtok_r(NULL, " ", &save);

    if (cmd == NULL || status == NULL || strcmp(cmd, "RVR") != 0) goto malformed;

    if (strcmp(status, "NOK") == 0 || strcmp(status, "ERR") == 0) {
        if (strtok_r(NULL, " ", &save) != NULL) goto malformed;
        if (strcmp(status, "NOK") == 0)
            printf("Nenhum utilizador disponibiliza o ficheiro '%s'.\n", fn);
        else
            printf("O DS respondeu ERR (pedido invalido).\n");
        ok = 1;
        goto done;
    }
    if (strcmp(status, "OK") != 0) goto malformed;

    /*
     Parse entries. The format of publication_time is not fixed by the
     statement (it may contain a space, e.g. "2026-10-20 11:46:00"), so the
     time is taken as every token between label and AVL/NAV (1 to 3 tokens).
     */
    char *tok;
    while ((tok = strtok_r(NULL, " ", &save)) != NULL) {
        version_t e;
        memset(&e, 0, sizeof(e));

        if (!valid_uid(tok)) goto malformed;
        snprintf(e.uid, sizeof(e.uid), "%s", tok);

        tok = strtok_r(NULL, " ", &save);
        if (tok == NULL || !valid_fsize_str(tok)) goto malformed;
        e.fsize = strtol(tok, NULL, 10);

        tok = strtok_r(NULL, " ", &save);
        if (tok == NULL || !valid_label(tok)) goto malformed;
        snprintf(e.label, sizeof(e.label), "%s", tok);

        int time_tokens = 0;
        for (;;) {
            tok = strtok_r(NULL, " ", &save);
            if (tok == NULL) goto malformed;
            if (strcmp(tok, "AVL") == 0 || strcmp(tok, "NAV") == 0) break;
            if (++time_tokens > 3) goto malformed;
            size_t used = strlen(e.time);
            if (used + strlen(tok) + 2 > sizeof(e.time)) goto malformed;
            if (used > 0) strcat(e.time, " ");
            strcat(e.time, tok);
        }
        if (time_tokens == 0) goto malformed;
        e.available = (strcmp(tok, "AVL") == 0);

        version_t *nv = realloc(v, (size_t) (count + 1) * sizeof(*v));
        if (nv == NULL) {
            fprintf(stderr, "Sem memoria.\n");
            ok = 1;
            goto done;
        }
        v = nv;
        v[count++] = e;
    }

    if (count == 0) {
        printf("Nenhum utilizador disponibiliza o ficheiro '%s'.\n", fn);
    } else {
        printf("Versoes de '%s' (%d):\n", fn, count);
        printf("  %-6s  %10s  %-20s  %-20s  %s\n",
               "UID", "Tamanho(B)", "Label", "Publicado em", "Estado");
        for (int i = 0; i < count; i++)
            printf("  %-6s  %10ld  %-20s  %-20s  %s\n",
                   v[i].uid, v[i].fsize, v[i].label, v[i].time,
                   v[i].available ? "disponivel" : "indisponivel");
    }
    ok = 1;

malformed:
    if (!ok)
        printf("Resposta inesperada do DS: '%s'. Interacao terminada.\n", reply);
done:
    free(v);
    free(buf);
    free(reply);
}


/* User interface                                                     */

static void print_commands(void) {
    printf("Comandos disponiveis: login UID password | logout | unregister | exit\n"
           "                      publish filename label | remove filename | list\n"
           "                      versions filename\n");
}

static void process_line(app_state_t *st, char *line, int *keep_running) {
    /* strip trailing newline */
    line[strcspn(line, "\r\n")] = '\0';

    char verb[32] = "";
    char arg1[64] = "", arg2[64] = "", arg3[64] = "";
    int n = sscanf(line, "%31s %63s %63s %63s", verb, arg1, arg2, arg3);
    if (n < 1) return; /* empty line */

    if (strcmp(verb, "login") == 0) {
        if (n != 3) {
            printf("Uso: login UID password\n");
            return;
        }
        if (st->logged_in) {
            printf("Ja existe um utilizador com sessao iniciada. Faca logout primeiro.\n");
            return;
        }
        cmd_login(st, arg1, arg2);
    } else if (strcmp(verb, "logout") == 0) {
        if (n != 1) { printf("Uso: logout\n"); return; }
        cmd_logout(st);
    } else if (strcmp(verb, "unregister") == 0) {
        if (n != 1) { printf("Uso: unregister\n"); return; }
        cmd_unregister(st);
    } else if (strcmp(verb, "exit") == 0) {
        if (n != 1) { printf("Uso: exit\n"); return; }
        cmd_exit(st, keep_running);
    } else if (strcmp(verb, "publish") == 0) {
        if (n != 3) { printf("Uso: publish filename label\n"); return; }
        cmd_publish(st, arg1, arg2);
    } else if (strcmp(verb, "remove") == 0) {
        if (n != 2) { printf("Uso: remove filename\n"); return; }
        cmd_remove(st, arg1);
    } else if (strcmp(verb, "list") == 0) {
        if (n != 1) { printf("Uso: list\n"); return; }
        cmd_list(st);
    } else if (strcmp(verb, "versions") == 0) {
        if (n != 2) { printf("Uso: versions filename\n"); return; }
        cmd_versions(st, arg1);
    } else {
        printf("Comando desconhecido: '%s'\n", verb);
        print_commands();
    }
}


static void usage(const char *prog) {
    fprintf(stderr, "Uso: %s -m peerport [-n DSIP] [-p DSport]\n", prog);
}

int main(int argc, char *argv[]) {
    app_state_t st;
    memset(&st, 0, sizeof(st));
    snprintf(st.ds_ip, sizeof(st.ds_ip), "%s", DEFAULT_DS_IP);
    snprintf(st.ds_port, sizeof(st.ds_port), "%s", DEFAULT_DS_PORT);

    /* A write() to a TCP connection closed by the other side must not
       kill the process: get EPIPE instead of SIGPIPE. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    int opt;
    int have_peerport = 0;
    while ((opt = getopt(argc, argv, "m:n:p:")) != -1) {
        switch (opt) {
            case 'm':
                if (!valid_port(optarg)) {
                    fprintf(stderr, "peerport invalido: %s\n", optarg);
                    return 1;
                }
                normalise_port(st.peerport, sizeof(st.peerport), optarg);
                have_peerport = 1;
                break;
            case 'n':
                if (strlen(optarg) == 0 || strlen(optarg) >= sizeof(st.ds_ip)) {
                    fprintf(stderr, "DSIP invalido: %s\n", optarg);
                    return 1;
                }
                snprintf(st.ds_ip, sizeof(st.ds_ip), "%s", optarg);
                break;
            case 'p':
                if (!valid_port(optarg)) {
                    fprintf(stderr, "DSport invalido: %s\n", optarg);
                    return 1;
                }
                normalise_port(st.ds_port, sizeof(st.ds_port), optarg);
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Argumento inesperado: %s\n", argv[optind]);
        usage(argv[0]);
        return 1;
    }

    if (!have_peerport) {
        fprintf(stderr, "O argumento -m peerport e obrigatorio.\n");
        usage(argv[0]);
        return 1;
    }

    if (resolve_ds(&st) != 0) return 1;

    st.udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (st.udp_fd == -1) {
        perror("socket");
        return 1;
    }

    printf("NetBoX User application (Fase II)\n");
    printf("  peerport = %s\n", st.peerport);
    printf("  DS       = %s:%s\n", st.ds_ip, st.ds_port);
    print_commands();

    char line[MAX_LINE];
    int keep_running = 1;
    while (keep_running) {
        printf("> ");
        fflush(stdout);
        if (fgets(line, sizeof(line), stdin) == NULL) {
            /* EOF (e.g. Ctrl-D): do not leave a session open in the DS */
            if (st.logged_in) {
                printf("\nEOF com sessao ativa: a efetuar logout...\n");
                cmd_logout(&st);
            }
            break;
        }

        /* Line longer than the buffer: discard the rest of it */
        if (strchr(line, '\n') == NULL && strlen(line) == sizeof(line) - 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            printf("Linha demasiado longa, ignorada.\n");
            continue;
        }

        process_line(&st, line, &keep_running);
    }

    close(st.udp_fd);
    return 0;
}
