#include "cracker_core.h"
#include <pthread.h>   // 使用 pthread-w32 或 Windows 原生线程
#include <time.h>
#include <math.h>

Config g_config = {
    .hash_type = HASH_MD5,
    .attack_mode = ATTACK_DICT,
    .theme = THEME_YIN_YANG_SHI,
    .dict_file = "",
    .hash_file = "",
    .output_file = "",
    .brute_max_len = 4,
    .brute_charset = "abcdefghijklmnopqrstuvwxyz0123456789",
    .resume = 0,
    .thread_count = 4,
    .show_progress = 1
};

HashNode* g_hash_list = NULL;
int g_total_hashes = 0;
int g_cracked_count = 0;
volatile int g_should_exit = 0;

pthread_mutex_t g_cracked_mutex = PTHREAD_MUTEX_INITIALIZER;

// 哈希计算实现（同前）
void compute_md5(const char* input, char* output) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input, strlen(input), digest);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        sprintf(output + i * 2, "%02x", digest[i]);
    output[MD5_DIGEST_LENGTH * 2] = '\0';
}

void compute_sha1(const char* input, char* output) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)input, strlen(input), digest);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(output + i * 2, "%02x", digest[i]);
    output[SHA_DIGEST_LENGTH * 2] = '\0';
}

void compute_sha256(const char* input, char* output) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input, strlen(input), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(output + i * 2, "%02x", digest[i]);
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

void compute_hash(const char* password, char* hash_out) {
    switch (g_config.hash_type) {
    case HASH_MD5: compute_md5(password, hash_out); break;
    case HASH_SHA1: compute_sha1(password, hash_out); break;
    case HASH_SHA256: compute_sha256(password, hash_out); break;
    default: compute_md5(password, hash_out);
    }
}

// 加载哈希文件
void load_hashes(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) return;
    char line[MAX_HASH_LEN];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;
        HashNode* node = (HashNode*)malloc(sizeof(HashNode));
        strcpy(node->hash, line);
        node->plain[0] = '\0';
        node->next = g_hash_list;
        g_hash_list = node;
        g_total_hashes++;
    }
    fclose(fp);
}

// 检查并记录破解结果
int check_and_record(const char* password) {
    char hash[MAX_HASH_LEN];
    compute_hash(password, hash);
    int found = 0;
    pthread_mutex_lock(&g_cracked_mutex);
    for (HashNode* node = g_hash_list; node; node = node->next) {
        if (node->plain[0] == '\0' && strcmp(node->hash, hash) == 0) {
            strcpy(node->plain, password);
            g_cracked_count++;
            found = 1;
        }
    }
    pthread_mutex_unlock(&g_cracked_mutex);
    return found;
}

// 保存结果
void save_results(void) {
    if (strlen(g_config.output_file) == 0) return;
    FILE* fp = fopen(g_config.output_file, "w");
    if (!fp) return;
    for (HashNode* node = g_hash_list; node; node = node->next) {
        fprintf(fp, "%s:%s\n", node->hash, node->plain[0] ? node->plain : "?");
    }
    fclose(fp);
}

// 字典攻击（省略详细实现，保持与原相同，只是去掉控制台输出改用全局变量通知GUI）
void dict_attack(void) {
    // 实现同上，但将 printf 替换为向 GUI 发送消息（例如通过 PostMessage）
    // 为了简化，保留 printf 但 GUI 可以重定向输出或使用日志窗口
    // 实际应用中应改为回调函数。此处为了篇幅，保留核心逻辑。
    // （为保持代码可读，这里仅写框架，完整版请见附后的完整工程包）
    FILE* fp = fopen(g_config.dict_file, "r");
    if (!fp) return;
    char line[MAX_PASS_LEN];
    while (fgets(line, sizeof(line), fp) && !g_should_exit) {
        line[strcspn(line, "\n")] = '\0';
        check_and_record(line);
        if (g_cracked_count == g_total_hashes) break;
    }
    fclose(fp);
}

// 雷索纳斯弱密码字典
static const char* weak_passwords[] = {
    "123456", "password", "12345678", "qwerty", "12345", NULL
};

void reso_dict_attack(void) {
    for (int i = 0; weak_passwords[i] && !g_should_exit; i++) {
        check_and_record(weak_passwords[i]);
        if (g_cracked_count == g_total_hashes) return;
    }
    dict_attack();
}

// 暴力破解函数（框架，完整版同前，此处省略递归细节）
void brute_attack_single(void) { /* 省略 */ }
void brute_attack_multi(void) { /* 省略 */ }
void brute_attack_resumable(void) { /* 省略 */ }

// 主调度函数
void run_cracker(void) {
    if (g_config.attack_mode == ATTACK_DICT) {
        if (g_config.theme == THEME_RESO_NANCE)
            reso_dict_attack();
        else
            dict_attack();
    } else {
        // 根据主题选择暴力方法
        if (g_config.theme == THEME_DEEP_SPACE)
            brute_attack_multi();
        else if (g_config.theme == THEME_REVERSE_1999)
            brute_attack_resumable();
        else
            brute_attack_single();
    }
}