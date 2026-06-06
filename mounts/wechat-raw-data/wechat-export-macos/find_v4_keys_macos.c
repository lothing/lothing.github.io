/*
 * macOS WeChat V4 binary key scanner.
 *
 * This complements find_all_keys_macos.c. The original scanner only searches
 * x'<64hex><32salt>' strings. Current WeChat 4.x builds may keep raw 32-byte
 * data keys near binary patterns instead.
 */

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <dirent.h>
#include <ftw.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_DBS 512
#define MAX_KEYS 1024
#define PAGE_SZ 4096
#define KEY_SZ 32
#define SALT_SZ 16
#define IV_SZ 16
#define HMAC_SZ 64
#define RESERVE_SZ 80
#define CHUNK_SIZE (4 * 1024 * 1024)

typedef struct {
    char rel[256];
    unsigned char page1[PAGE_SZ];
} db_entry_t;

typedef struct {
    char rel[256];
    char key_hex[65];
    char mode[16];
} found_key_t;

static db_entry_t g_dbs[MAX_DBS];
static int g_db_count = 0;
static found_key_t g_found[MAX_KEYS];
static int g_found_count = 0;
static int g_scan_zero = 0;
static int g_candidate_count = 0;
static int g_candidate_limit = 20000;
static char g_db_root[768] = {0};
static char g_db_filter[256] = {0};

static const unsigned char PATTERN_FTS5[] = {0x20, 0x66, 0x74, 0x73, 0x35, 0x28, 0x25, 0x00};
static const unsigned char PATTERN_ZERO16[] = {0};

static void hex_encode(const unsigned char *in, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int all_zero(const unsigned char *p, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0) return 0;
    }
    return 1;
}

static int has_double_zero(const unsigned char *p, size_t len) {
    if (len < 2) return 0;
    for (size_t i = 0; i + 1 < len; i++) {
        if (p[i] == 0 && p[i + 1] == 0) return 1;
    }
    return 0;
}

static void derive_v4(const unsigned char *raw_key, const unsigned char *salt,
                      unsigned char *enc_key, unsigned char *mac_key) {
    CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)raw_key, KEY_SZ, salt, SALT_SZ,
                         kCCPRFHmacAlgSHA512, 256000, enc_key, KEY_SZ);
    unsigned char mac_salt[SALT_SZ];
    for (int i = 0; i < SALT_SZ; i++) mac_salt[i] = salt[i] ^ 0x3a;
    CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)enc_key, KEY_SZ, mac_salt, SALT_SZ,
                         kCCPRFHmacAlgSHA512, 2, mac_key, KEY_SZ);
}

static void derive_direct(const unsigned char *enc_key_in, const unsigned char *salt,
                          unsigned char *enc_key, unsigned char *mac_key) {
    memcpy(enc_key, enc_key_in, KEY_SZ);
    unsigned char mac_salt[SALT_SZ];
    for (int i = 0; i < SALT_SZ; i++) mac_salt[i] = salt[i] ^ 0x3a;
    CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)enc_key, KEY_SZ, mac_salt, SALT_SZ,
                         kCCPRFHmacAlgSHA512, 2, mac_key, KEY_SZ);
}

static int validate_with_mode(const unsigned char *page1, const unsigned char *key, int v4_mode) {
    unsigned char enc_key[KEY_SZ], mac_key[KEY_SZ], digest[CC_SHA512_DIGEST_LENGTH];
    if (v4_mode) derive_v4(key, page1, enc_key, mac_key);
    else derive_direct(key, page1, enc_key, mac_key);

    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA512, mac_key, KEY_SZ);
    CCHmacUpdate(&ctx, page1 + SALT_SZ, PAGE_SZ - RESERVE_SZ + IV_SZ - SALT_SZ);
    unsigned char pgno[4] = {1, 0, 0, 0};
    CCHmacUpdate(&ctx, pgno, sizeof(pgno));
    CCHmacFinal(&ctx, digest);
    return memcmp(digest, page1 + PAGE_SZ - HMAC_SZ, HMAC_SZ) == 0;
}

static int add_found(const char *rel, const unsigned char *key, const char *mode) {
    char key_hex[65];
    hex_encode(key, KEY_SZ, key_hex);
    for (int i = 0; i < g_found_count; i++) {
        if (strcmp(g_found[i].rel, rel) == 0 && strcmp(g_found[i].key_hex, key_hex) == 0) {
            return 0;
        }
    }
    if (g_found_count >= MAX_KEYS) return 0;
    strncpy(g_found[g_found_count].rel, rel, sizeof(g_found[g_found_count].rel) - 1);
    strcpy(g_found[g_found_count].key_hex, key_hex);
    strncpy(g_found[g_found_count].mode, mode, sizeof(g_found[g_found_count].mode) - 1);
    g_found_count++;
    printf("  matched %s (%s)\n", rel, mode);
    return 1;
}

static void test_candidate(const unsigned char *key) {
    if (g_candidate_count++ >= g_candidate_limit) return;
    if (g_candidate_count % 100 == 0) {
        printf("  candidates tested: %d\n", g_candidate_count);
        fflush(stdout);
    }
    if (has_double_zero(key, KEY_SZ)) return;
    for (int i = 0; i < g_db_count; i++) {
        if (validate_with_mode(g_dbs[i].page1, key, 1)) {
            add_found(g_dbs[i].rel, key, "v4-pbkdf2");
        }
        if (validate_with_mode(g_dbs[i].page1, key, 0)) {
            add_found(g_dbs[i].rel, key, "direct");
        }
    }
}

static int collect_db(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)ftwbuf;
    if (typeflag != FTW_F || g_db_count >= MAX_DBS) return 0;
    size_t len = strlen(fpath);
    if (len < 3 || strcmp(fpath + len - 3, ".db") != 0) return 0;

    FILE *f = fopen(fpath, "rb");
    if (!f) return 0;
    size_t n = fread(g_dbs[g_db_count].page1, 1, PAGE_SZ, f);
    fclose(f);
    if (n != PAGE_SZ) return 0;
    if (memcmp(g_dbs[g_db_count].page1, "SQLite format 3", 15) == 0) return 0;

    const char *rel = strstr(fpath, "db_storage/");
    if (rel) rel += strlen("db_storage/");
    else {
        rel = strrchr(fpath, '/');
        rel = rel ? rel + 1 : fpath;
    }
    if (g_db_filter[0] && strstr(rel, g_db_filter) == NULL) return 0;
    strncpy(g_dbs[g_db_count].rel, rel, sizeof(g_dbs[g_db_count].rel) - 1);
    g_db_count++;
    return 0;
}

static void collect_dbs(const char *home) {
    if (g_db_root[0]) {
        nftw(g_db_root, collect_db, 20, FTW_PHYS);
        return;
    }

    char db_base_dir[512];
    snprintf(db_base_dir, sizeof(db_base_dir),
             "%s/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files", home);
    DIR *xdir = opendir(db_base_dir);
    if (!xdir) return;
    struct dirent *ent;
    while ((ent = readdir(xdir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char storage_path[768];
        snprintf(storage_path, sizeof(storage_path), "%s/%s/db_storage", db_base_dir, ent->d_name);
        struct stat st;
        if (stat(storage_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            nftw(storage_path, collect_db, 20, FTW_PHYS);
        }
    }
    closedir(xdir);
}

static void scan_buffer(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i + sizeof(PATTERN_FTS5) + 80 < len; i++) {
        if (memcmp(buf + i, PATTERN_FTS5, sizeof(PATTERN_FTS5)) == 0) {
            int offsets[] = {16, -80, 64};
            for (size_t j = 0; j < sizeof(offsets) / sizeof(offsets[0]); j++) {
                long off = (long)i + offsets[j];
                if (off >= 0 && off + KEY_SZ <= (long)len) test_candidate(buf + off);
            }
        }
    }

    if (!g_scan_zero) return;

    for (size_t i = KEY_SZ; i + 16 < len; i++) {
        if (memcmp(buf + i, PATTERN_ZERO16, 16) != 0) continue;
        if (i > 0 && buf[i - 1] == 0) continue;
        if (i + 16 < len && buf[i + 16] == 0) continue;
        test_candidate(buf + i - KEY_SZ);
        i += 15;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <pid> [--db-root PATH] [--db-filter TEXT] [--zero] [--limit N]\n", argv[0]);
        return 1;
    }
    pid_t pid = atoi(argv[1]);
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--zero") == 0) {
            g_scan_zero = 1;
        } else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            g_candidate_limit = atoi(argv[++i]);
            if (g_candidate_limit <= 0) g_candidate_limit = 20000;
        } else if (strcmp(argv[i], "--db-root") == 0 && i + 1 < argc) {
            strncpy(g_db_root, argv[++i], sizeof(g_db_root) - 1);
        } else if (strcmp(argv[i], "--db-filter") == 0 && i + 1 < argc) {
            strncpy(g_db_filter, argv[++i], sizeof(g_db_filter) - 1);
        }
    }
    const char *home = getenv("HOME");
    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        struct passwd *pw = getpwnam(sudo_user);
        if (pw && pw->pw_dir) home = pw->pw_dir;
    }
    if (!home) {
        fprintf(stderr, "HOME is not set; pass --db-root explicitly.\n");
        return 1;
    }

    collect_dbs(home);
    printf("Loaded %d encrypted DB first pages; zero scan=%s; candidate limit=%d\n",
           g_db_count, g_scan_zero ? "on" : "off", g_candidate_limit);

    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %d\n", kr);
        return 1;
    }
    printf("Got task port for PID %d\n", pid);

    size_t total_scanned = 0;
    int region_count = 0;
    mach_vm_address_t addr = 0;
    while (1) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name;
        kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &info_count, &obj_name);
        if (kr != KERN_SUCCESS) break;
        if (size == 0) { addr++; continue; }
        if (info.protection & VM_PROT_READ) {
            region_count++;
            mach_vm_address_t ca = addr;
            while (ca < addr + size) {
                mach_vm_size_t cs = addr + size - ca;
                if (cs > CHUNK_SIZE) cs = CHUNK_SIZE;
                vm_offset_t data = 0;
                mach_msg_type_number_t dc = 0;
                kr = mach_vm_read(task, ca, cs, &data, &dc);
                if (kr == KERN_SUCCESS && dc > 0) {
                    total_scanned += dc;
                    scan_buffer((unsigned char *)data, dc);
                    mach_vm_deallocate(mach_task_self(), data, dc);
                }
                ca += cs;
            }
        }
        addr += size;
    }
    printf("Scan complete: %zuMB scanned, %d regions, %d candidates, %d DB matches\n",
           total_scanned / 1024 / 1024, region_count, g_candidate_count, g_found_count);

    FILE *fp = fopen("all_keys.json", "w");
    if (!fp) {
        perror("all_keys.json");
        return 1;
    }
    fprintf(fp, "{\n");
    for (int i = 0; i < g_found_count; i++) {
        fprintf(fp, "%s  \"%s\": {\"enc_key\": \"%s\", \"mode\": \"%s\"}",
                i ? ",\n" : "", g_found[i].rel, g_found[i].key_hex, g_found[i].mode);
    }
    fprintf(fp, "\n}\n");
    fclose(fp);
    return g_found_count > 0 ? 0 : 2;
}
